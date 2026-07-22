# Test vectors: original, hand-built from RFC 4511 grammar — https://www.rfc-editor.org/rfc/rfc4511.txt

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

=== TEST 1: LDAPResult fields must have the right ASN.1 types
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- a wrong ASN.1 type in the resultCode slot is rejected strictly: nil result AND an
            -- error, never a mistyped result table (an OCTET STRING resultCode becomes "\0",
            -- compares ~= 0, so a successful bind would read as failure)
            local cases = {
                { "NULL",         "30 0b 02 01 01 61 06 05 00 04 00 04 00" },
                { "BOOLEAN",      "30 0c 02 01 01 61 07 01 01 ff 04 00 04 00" },
                { "OCTET STRING", "30 0c 02 01 01 61 07 04 01 00 04 00 04 00" },
                { "SEQUENCE",     "30 0b 02 01 01 61 06 30 00 04 00 04 00" },
            }
            for _, c in ipairs(cases) do
                local res, err = protocol.decode_message(ldap_hex(c[2]))
                assert(res == nil, c[1] .. " resultCode must not produce a result table")
                assert(err ~= nil, c[1] .. " resultCode must report an error")
            end

            -- matchedDN slot holds an INTEGER: matched_dn becomes the number 5
            local bad3, err3 = protocol.decode_message(ldap_hex("30 0d 02 01 01 61 08 0a 01 00 02 01 05 04 00"))
            assert(bad3 == nil and err3 ~= nil, "non-string matchedDN must be rejected")

            -- consequence guard: a decoded result_code must survive the client error formatter,
            -- which string-concatenates it into "Unknown error occurred (code: ...)"
            local good = assert(protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(type(good.result_code) == "number", "result_code is a number")
            local built = pcall(function()
                return "Unknown error occurred (code: " .. good.result_code .. ")"
            end)
            assert(built, "client error formatter throws on this resultCode")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: a repeated attribute type still decodes to a well-formed attribute map
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- PartialAttributeList carries "uid" twice: {"a"} then {"b"}
            local pkt = ldap_hex([[30 22 02 01 03 64 1d
                04 01 78
                30 18
                   30 0a 04 03 75 69 64 31 03 04 01 61
                   30 0a 04 03 75 69 64 31 03 04 01 62]])
            local res, err = protocol.decode_message(pkt)
            assert(res ~= nil, "duplicate attribute type must decode: " .. tostring(err))
            assert(res.entry_dn == "x", "entry_dn")
            local uid = res.attributes.uid
            assert(type(uid) == "table", "uid must be an array, got " .. type(uid))
            assert(#uid == 1 and (uid[1] == "a" or uid[1] == "b"),
                   "uid must hold one of the values actually sent")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
