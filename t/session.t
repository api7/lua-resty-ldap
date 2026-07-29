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

=== TEST 1: bind and search share one connection until it is released
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local c = ldap_client:new("127.0.0.1", 1389)

            -- prime the bind pool so reuse below is observable via getreusedtimes()
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            assert(c:set_keepalive())

            local ok, err = c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword")
            assert(ok, "bind: " .. tostring(err))
            local session_sock = c.socket
            assert(session_sock:getreusedtimes() >= 1,
                   "a released bind connection should have been pooled and reused")

            local res, serr = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "search: " .. tostring(serr))
            assert(#res == 1 and res[1].entry_dn == "dc=example,dc=org", "base entry")

            -- the search must have run on the bind's connection, not its own
            assert(rawequal(c.socket, session_sock), "socket changed mid-session")

            assert(c:set_keepalive())
            assert(c.socket == nil, "set_keepalive releases the connection")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: a lone operation needs no explicit connect
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
            assert(c.socket ~= nil, "the connection is held until released")
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

=== TEST 3: close() drops the connection and the next op opens another
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            local session_sock = c.socket
            assert(session_sock ~= nil, "the bind opened a connection")

            assert(c:close())
            assert(c.socket == nil, "close drops the socket")

            -- a later op opens its own connection
            local res, err = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "search after close: " .. tostring(err))
            assert(#res == 1, "one entry")
            assert(not rawequal(c.socket, session_sock), "closed socket was reused")
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

=== TEST 4: a hard socket error detaches the connection instead of stranding it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))

            -- kill the held connection underneath the client
            c.socket:close()

            local ok, err = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(not ok, "a search on a dead socket must fail")
            assert(err ~= nil, "a search on a dead socket reports an error")

            -- the failure must detach the dead socket, not strand the client on it
            assert(c.socket == nil, "hard error left a dead socket attached")

            -- and the client is usable again without an explicit close()
            local res, serr = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "client unusable after a hard error: " .. tostring(serr))
            assert(#res == 1, "one entry")
            assert(c:set_keepalive())

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
attempt to send data on a closed socket

=== TEST 5: a bind on an already-open connection stays on it; close ends the mix
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            -- an unbound search opens the connection (anonymous pool)
            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))
            local session_sock = c.socket

            -- a later bind runs on that same connection
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            assert(rawequal(c.socket, session_sock), "the bind switched connections")

            -- close: pooling would hand the admin identity to the next unbound caller
            assert(c:close())

            -- so the next anonymous search cannot draw the bound connection
            local d = ldap_client:new("127.0.0.1", 1389)
            local res, serr = d:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "anonymous search: " .. tostring(serr))
            assert(d.socket:getreusedtimes() == 0,
                   "the bound connection leaked into the anonymous pool")
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

=== TEST 6: set_keepalive after a bind on an anonymous-pool connection closes it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            -- an unbound search opens the connection (anonymous pool)
            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))

            -- a later bind runs on that same connection
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))

            -- the client must close here instead of pooling: this connection came
            -- from the anonymous pool, and returning it would hand the admin
            -- identity to the next unbound caller
            assert(c:set_keepalive())
            assert(c.socket == nil, "set_keepalive releases the connection")

            local d = ldap_client:new("127.0.0.1", 1389)
            local res, serr = d:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "anonymous search: " .. tostring(serr))
            assert(d.socket:getreusedtimes() == 0,
                   "the bound connection leaked into the anonymous pool")
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
