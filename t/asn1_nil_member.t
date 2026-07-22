# pyasn1 v0.6.4 Sequence/SetDecoderTestCase DefMode: https://github.com/pyasn1/pyasn1/blob/v0.6.4/tests/codec/ber/test_decoder.py

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

=== TEST 1: an undecodable member must error, never shrink the array
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- SET { "A", BOOLEAN TRUE }: BOOLEAN has no decoder; slot silently dropped -> {"A"}.
            local _, v, err = asn1.decode(ldap_hex("31 06 04 01 41 01 01 ff"))
            assert(err ~= nil, "undecodable SET member must report an error")
            assert(v == nil, "no value when a member cannot be decoded")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: position is not silently reindexed, and all-undecodable is not "empty"
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- Undecodable member FIRST: currently yields {"A"} at index 1 (member 2's value).
            local _, v, err = asn1.decode(ldap_hex("31 06 01 01 ff 04 01 41"))
            assert(err ~= nil, "leading undecodable member must report an error")
            assert(v == nil, "no value when a member cannot be decoded")

            -- SET with only an undecodable member currently decodes to {}, like a genuine empty SET.
            local _, v2, err2 = asn1.decode(ldap_hex("31 03 01 01 ff"))
            assert(err2 ~= nil, "SET of one undecodable member must error")
            assert(v2 == nil, "no value for an all-undecodable SET")

            -- ...while a genuinely empty SET stays a clean empty array.
            local _, v3, err3 = asn1.decode(ldap_hex("31 00"))
            assert(err3 == nil, "empty SET is still valid: " .. tostring(err3))
            assert(type(v3) == "table" and #v3 == 0, "empty SET decodes to {}")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: NULL members and EOC filler inside a definite-length container
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- SEQUENCE { OCTET STRING "A", NULL }: the NULL slot vanishes -> {"A"}
            local _, v, err = asn1.decode(ldap_hex("30 05 04 01 41 05 00"))
            assert(err ~= nil, "NULL member must report an error, not vanish")
            assert(v == nil, "no value when a NULL member is dropped")

            -- Stray EOC filler in a definite-length container (30 02); tag-0 TLV that vanishes -> {}.
            local _, v2, err2 = asn1.decode(ldap_hex("30 02 00 00"))
            assert(err2 ~= nil, "EOC filler in a definite-length SEQUENCE must error")
            assert(v2 == nil, "no value for EOC filler")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: an attribute value must not silently vanish from a SearchResultEntry
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- Via protocol.lua: SearchResultEntry vals { "a", NULL } (msgID 1, dc=x, cn).
            local pkt = ldap_hex([[30 1a 02 01 01 64 15
                04 04 64 63 3d 78
                30 0d 30 0b 04 02 63 6e
                      31 05 04 01 61 05 00]])
            local res, err = protocol.decode_message(pkt)
            assert(res == nil, "entry with an undecodable attribute value is rejected")
            assert(err ~= nil, "undecodable attribute value reports an error")

            -- Same shape with a BOOLEAN instead of NULL in the vals SET.
            local pkt2 = ldap_hex([[30 1b 02 01 01 64 16
                04 04 64 63 3d 78
                30 0e 30 0c 04 02 63 6e
                      31 06 04 01 61 01 01 ff]])
            local res2, err2 = protocol.decode_message(pkt2)
            assert(res2 == nil and err2 ~= nil, "BOOLEAN in vals SET reports an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: guard -- well-formed containers keep their full arity and stay error-free
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- Every member has a decoder: nothing may be lost and nothing may error.
            local _, v, err = asn1.decode(ldap_hex("31 06 04 01 41 04 01 42"))
            assert(err == nil, "well-formed SET must not error: " .. tostring(err))
            assert(#v == 2 and v[1] == "A" and v[2] == "B", "both members present")

            -- Mixed member types inside a SEQUENCE: INTEGER, OCTET STRING, ENUMERATED
            local _, v2, err2 = asn1.decode(ldap_hex("30 09 02 01 07 04 01 41 0a 01 00"))
            assert(err2 == nil, "mixed SEQUENCE must not error: " .. tostring(err2))
            assert(#v2 == 3 and v2[1] == 7 and v2[2] == "A" and v2[3] == 0, "three members present")

            -- A real multi-valued entry still round-trips with full arity.
            local res = assert(protocol.decode_message(ldap_hex([[30 49 02 01 02 64 44
                04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 63 6f 6d
                30 2f
                   30 1c 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73
                         31 0d 04 03 74 6f 70 04 06 64 6f 6d 61 69 6e
                   30 0f 04 02 64 63
                         31 09 04 07 65 78 61 6d 70 6c 65]])))
            assert(#res.attributes.objectClass == 2, "objectClass keeps 2 values")
            assert(#res.attributes.dc == 1, "dc keeps 1 value")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
