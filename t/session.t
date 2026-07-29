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

            -- prime the pool so reuse below is observable via getreusedtimes()
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

=== TEST 5: a bound connection is pooled as-is and the next session rebinds on it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            -- an unbound search opens the connection, a bind runs on it, and the
            -- release pools it unchanged: bind state is not part of the pool key
            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))
            local session_sock = c.socket
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            assert(rawequal(c.socket, session_sock), "the bind switched connections")
            assert(c:set_keepalive())

            -- the next session draws that same connection and rebinds to reach its
            -- own desired state: each bind resets the session (RFC 4513 s4)
            local d = ldap_client:new("127.0.0.1", 1389)
            assert(d:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1"))
            assert(d.socket:getreusedtimes() == 1,
                   "the bound connection should have been pooled and reused, got " ..
                   d.socket:getreusedtimes())
            local res, serr = d:search("ou=users,dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "search on the rebound connection: " .. tostring(serr))
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
