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

=== TEST 1: search by login attribute (uid) returns an entry whose RDN is cn
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")
            local filter = require("resty.ldap.filter")

            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))

            local login = "jdoe"
            local flt = "(uid=" .. filter.escape(login) .. ")"
            local res, err = c:search("ou=users,dc=example,dc=org",
                protocol.SEARCH_SCOPE_WHOLE_SUBTREE, nil, nil, nil, nil, flt, {"uid", "description"})
            assert(res, "search: " .. tostring(err))
            assert(#res == 1, "exactly one entry, got " .. #res)
            assert(res[1].entry_dn == "cn=Jane Doe,ou=users,dc=example,dc=org",
                "DN is the RDN-based DN: " .. tostring(res[1].entry_dn))
            assert(res[1].attributes.uid[1] == "jdoe", "uid value")
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

=== TEST 2: binary attribute value with embedded NUL survives end-to-end
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")
            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            local res = assert(c:search("ou=users,dc=example,dc=org",
                protocol.SEARCH_SCOPE_WHOLE_SUBTREE, nil, nil, nil, nil,
                "(uid=jdoe)", {"description"}))
            assert(#res == 1, "one entry")
            local d = res[1].attributes.description[1]
            assert(#d == 3, "description length is 3 (not truncated at NUL): got " .. #d)
            assert(d == "\1\0\2", "description bytes preserved")
            c:close()
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
