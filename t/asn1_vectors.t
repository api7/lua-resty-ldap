# Vectors cross-checked against pyasn1 v0.6.4, rasn v0.6.1, and Go encoding/asn1.

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

=== TEST 1: tags with no decoder must error, never return a silent nil
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- Well-formed universal TLVs whose tag has no decoder entry must error, not return nil.
            local cases = {
                { "01 01 ff", "BOOLEAN true" },
                { "01 01 00", "BOOLEAN false" },
                { "01 01 01 00 78 32 32", "BOOLEAN with trailing bytes" },
                { "05 00", "NULL" },
                { "06 01 55", "OID 2.5" },
                { "06 04 55 02 c0 00", "OID 2.5.2.8192" },
                { "03 02 07 00", "BIT STRING" },
                { "1a 05 4a 6f 6e 65 73", "VisibleString \"Jones\"" },
                { "16 05 53 6d 69 74 68", "IA5String \"Smith\"" },
            }
            for _, c in ipairs(cases) do
                local off, v, err = asn1.decode(ldap_hex(c[1]))
                assert(err ~= nil, c[2] .. " must report an explicit error, got err=nil value=" ..
                                   tostring(v) .. " off=" .. tostring(off))
                assert(v == nil, c[2] .. " must not yield a value")
            end

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: ported vectors that must KEEP working (BER leniency preserved)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- Guard rail for the hardening work: these must not become errors.

            local _, os1, e1 = asn1.decode(
                ldap_hex("04 0f 51 75 69 63 6b 20 62 72 6f 77 6e 20 66 6f 78"))
            assert(e1 == nil and os1 == "Quick brown fox", "primitive OCTET STRING")

            local _, os2, e2 = asn1.decode(ldap_hex("04 06 01 02 03 04 05 06"))
            assert(e2 == nil and os2 == "\1\2\3\4\5\6", "binary OCTET STRING round-trips")

            local _, os3, e3 = asn1.decode(ldap_hex("04 81 03 41 42 43"))
            assert(e3 == nil and os3 == "ABC", "non-minimal length must remain accepted")

            local _, os4, e4 = asn1.decode(ldap_hex("04 88 00 00 00 00 00 00 00 05") .. "hello")
            assert(e4 == nil and os4 == "hello", "8-byte long-form length must remain accepted")

            local ints = {
                { "02 03 00 80 00", 32768 },
                { "02 02 7f ff",    32767 },
                { "02 02 01 00",    256 },
                { "02 01 7f",       127 },
                { "02 01 ff",       -1 },
                { "02 03 ff 7f ff", -32769 },
            }
            for _, c in ipairs(ints) do
                local _, v, err = asn1.decode(ldap_hex(c[1]))
                assert(err == nil and v == c[2],
                       "rasn integer vector " .. c[1] .. " -> " .. tostring(v))
            end

            local go_ints = {
                { "02 01 00",       0 },
                { "02 02 00 80",    128 },
                { "02 01 80",       -128 },
                { "02 02 ff 7f",    -129 },
            }
            for _, c in ipairs(go_ints) do
                local _, v, err = asn1.decode(ldap_hex(c[1]))
                assert(err == nil and v == c[2],
                       "go int64 vector " .. c[1] .. " -> " .. tostring(v))
            end

            local _, p12 = asn1.decode(ldap_hex("02 01 0c"))
            local _, n12 = asn1.decode(ldap_hex("02 01 f4"))
            assert(p12 == 12 and n12 == -12, "pyasn1 12 / -12")

            local _, chunked, ec = asn1.decode(
                ldap_hex("24 17 04 04 51 75 69 63 04 04 6b 20 62 72 04 04 6f 77 6e 20 04 03 66 6f 78"))
            assert(chunked == nil and ec ~= nil, "constructed OCTET STRING stays rejected")

            local deep = ldap_hex("05 00")
            for _ = 1, 150 do deep = asn1.put_object(16, asn1.CLASS.UNIVERSAL, 1, deep) end
            local _, dv, de = asn1.decode(deep)
            assert(dv == nil and de ~= nil, "deep nesting is bounded")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
