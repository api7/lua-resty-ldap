use Test::Nginx::Socket::Lua;

log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;/usr/share/lua/5.1/?.lua;;';
    lua_package_cpath 'deps/lib/lua/5.1/?.so;;';
    resolver 127.0.0.53;
_EOC_

run_tests();

__DATA__

=== TEST 1: bind and search share one pinned connection
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local c = ldap_client:new("127.0.0.1", 1389)

            -- prime the keepalive pool with a single-shot op, so the pinned
            -- checkout below is observable via getreusedtimes() (a brand-new
            -- connection always reports 0, pooled ones report >= 1)
            assert(c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))

            assert(c:connect())
            local pinned_sock = c.socket

            local ok, err = c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword")
            assert(ok, "bind: " .. tostring(err))

            local res, serr = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "search: " .. tostring(serr))
            assert(#res == 1 and res[1].entry_dn == "dc=example,dc=org", "base entry")

            -- the socket must have been reused (bind + search on the same conn)
            assert(rawequal(c.socket, pinned_sock), "socket changed mid-session")
            assert(c.socket:getreusedtimes() >= 1, "connection was not pinned/reused")

            assert(c:set_keepalive())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: single-shot (no session) still works unchanged
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")
            local c = ldap_client:new("127.0.0.1", 1389)
            local res = assert(c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))
            assert(#res == 1, "one entry")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: close() unpins the session and the next op reconnects
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:connect())
            assert(c.pinned, "connect pins the session")
            local pinned_sock = c.socket

            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            assert(rawequal(c.socket, pinned_sock), "socket changed mid-session")

            assert(c:close())
            assert(c.pinned == nil, "close unpins")
            assert(c.socket == nil, "close drops the socket")

            -- a later op checks out its own connection, still unpinned
            local res, err = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "search after close: " .. tostring(err))
            assert(#res == 1, "one entry")
            assert(c.pinned == nil, "single-shot op stays unpinned")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: a hard socket error unpins the session instead of stranding it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:connect())

            -- kill the pinned connection underneath the client
            c.socket:close()

            local ok, err = c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword")
            assert(not ok, "bind on a dead socket must fail")
            assert(err ~= nil, "bind on a dead socket reports an error")

            -- the failure must release the pin, not strand the client on it
            assert(c.pinned == nil, "hard error left the session pinned")
            assert(c.socket == nil, "hard error left a dead socket attached")

            -- and the client is usable again without an explicit close()
            local res, serr = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "client unusable after a hard error: " .. tostring(serr))
            assert(#res == 1, "one entry")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
attempt to send data on a closed socket

=== TEST 5: releasing a bound session closes the socket instead of pooling it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            -- prime the pool so the pinned checkout below is observably reused
            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))

            assert(c:connect())
            assert(c.socket:getreusedtimes() >= 1, "pinned checkout should hit the pool")
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            assert(c:set_keepalive()) -- bound: must close, not pool

            -- a new anonymous client must get a fresh connection; its search
            -- must not inherit the admin identity
            local d = ldap_client:new("127.0.0.1", 1389)
            assert(d:connect())
            assert(d.socket:getreusedtimes() == 0,
                   "admin-bound socket leaked into the pool")
            local res, serr = d:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "anonymous search: " .. tostring(serr))
            assert(#res == 1 and res[1].entry_dn == "dc=example,dc=org", "base entry")
            assert(d:set_keepalive())

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
