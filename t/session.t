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
