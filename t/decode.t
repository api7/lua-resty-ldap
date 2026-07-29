use Test::Nginx::Socket::Lua;
log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;t/lib/?.lua;/usr/share/lua/5.1/?.lua;;';
    lua_package_cpath 'deps/lib/lua/5.1/?.so;;';
    resolver 127.0.0.53;
_EOC_

run_tests();

__DATA__

=== TEST 1: BindResponse success -> LDAPResult shape
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local decode   = protocol.decode_message
            local ldap_hex = require("ldap_hex")
            local res = assert(decode(ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(res.protocol_op == protocol.APP_NO.BindResponse, "op " .. tostring(res.protocol_op))
            assert(res.result_code == 0, "code")
            assert(res.matched_dn == "", "matched_dn")
            assert(res.diagnostic_msg == "", "diag")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: SearchResultDone with nonzero result code
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local decode   = protocol.decode_message
            local ldap_hex = require("ldap_hex")
            local res = assert(decode(ldap_hex("30 0c 02 01 02 65 07 0a 01 20 04 00 04 00")))
            assert(res.protocol_op == protocol.APP_NO.SearchResultDone, "op")
            assert(res.result_code == 32, "code " .. tostring(res.result_code))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: SearchResultEntry, binary value with embedded NUL stays an array, untruncated
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local decode   = protocol.decode_message
            local ldap_hex = require("ldap_hex")
            -- entry_dn "x"; attribute s = { "\1\0\2" } (3 bytes, contains NUL)
            local res = assert(decode(ldap_hex("30 16 02 01 03 64 11 04 01 78 30 0c 30 0a 04 01 73 31 05 04 03 01 00 02")))
            assert(res.protocol_op == protocol.APP_NO.SearchResultEntry, "op")
            assert(res.entry_dn == "x", "dn " .. tostring(res.entry_dn))
            assert(type(res.attributes.s) == "table", "s is array")
            assert(#res.attributes.s == 1, "one value")
            assert(#res.attributes.s[1] == 3, "value length " .. #res.attributes.s[1])
            assert(res.attributes.s[1] == "\1\0\2", "value bytes")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: empty vals SET and empty attribute list
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local decode   = require("resty.ldap.protocol").decode_message
            local ldap_hex = require("ldap_hex")
            local res = assert(decode(ldap_hex(
                "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(type(res.attributes.s) == "table", "s is table")
            assert(#res.attributes.s == 0, "s empty")
            local res2 = assert(decode(ldap_hex("30 0a 02 01 03 64 05 04 01 78 30 00")))
            assert(res2.entry_dn == "x", "dn2")
            assert(next(res2.attributes) == nil, "no attributes")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
