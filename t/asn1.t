# Test vectors: rasn v0.6.1 (octet_string); Go go1.26.3 encoding/asn1 (int64TestData).

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

=== TEST 1: get_object reads tag/class/len/hl for short and long form
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- short form: 30 03 02 01 05  (SEQUENCE len 3)
            local o = assert(asn1.get_object(ldap_hex("30 03 02 01 05")))
            assert(o.tag == 16, "tag " .. o.tag)          -- SEQUENCE
            assert(o.class == asn1.CLASS.UNIVERSAL, "class")
            assert(o.cons == true, "cons")
            assert(o.len == 3, "len " .. o.len)
            assert(o.hl == 2, "hl " .. o.hl)
            assert(o.offset == 2, "offset " .. o.offset)

            -- long form: 30 81 82 <130 bytes>  (2-extra-byte header)
            local body = string.rep("\0", 130)
            local o2 = assert(asn1.get_object(ldap_hex("30 81 82") .. body))
            assert(o2.len == 130, "long len " .. o2.len)
            assert(o2.hl == 3, "long hl " .. o2.hl)       -- NOT 2

            -- application-tagged: 64 00  (SearchResultEntry, empty)
            local o3 = assert(asn1.get_object(ldap_hex("64 00")))
            assert(o3.tag == 4, "app tag " .. o3.tag)
            assert(o3.class == asn1.CLASS.APPLICATION, "app class")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: decode octet string is NUL-safe (regression: no strlen truncation)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- 04 05 41 42 00 43 44  => "AB\0CD" (5 bytes, embedded NUL)
            local _, v = asn1.decode(ldap_hex("04 05 41 42 00 43 44"))
            assert(#v == 5, "length " .. #v)               -- a strlen-based read would stop at the NUL
            assert(v == "AB\0CD", "value")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: decode integer, enumerated, and nested SEQUENCE/SET (uses hl, not +2)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, id = asn1.decode(ldap_hex("02 01 03"))
            assert(id == 3, "int " .. tostring(id))
            local _, code = asn1.decode(ldap_hex("0a 01 00"))
            assert(code == 0, "enum " .. tostring(code))

            -- SET OF two octet strings: 31 0d 04 03 746f70 04 06 646f6d61696e
            local _, vals = asn1.decode(ldap_hex("31 0d 04 03 74 6f 70 04 06 64 6f 6d 61 69 6e"))
            assert(type(vals) == "table", "set is table")
            assert(vals[1] == "top" and vals[2] == "domain", "set values")

            -- long-form SET (>=128 bytes of content) parses via hl, not +2
            local big = string.rep("\4\1X", 60)          -- 60 octet strings "X" = 180 bytes
            local seq = ldap_hex("31 81 b4") .. big              -- 0xb4 = 180
            local _, arr = asn1.decode(seq)
            assert(#arr == 60, "long set count " .. #arr)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: malformed input returns error, never crashes
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- claims 5 content bytes, only 2 present
            local off, v, err = asn1.decode(ldap_hex("30 05 02 01"))
            assert(v == nil, "no value on malformed")
            assert(err ~= nil, "error reported")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: decoder errors surface, not swallowed as empty success
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- truncated-child case is original: exercises the `stop` bound (asn1.lua:412)

            -- truncated child: outer len 3, inner OCTET STRING claims 5 but 1 present
            local _, v, err = asn1.decode(ldap_hex("30 03 04 05 41"))
            assert(v == nil, "no value for truncated child")
            assert(err ~= nil, "truncated child reports error")

            -- zero-length INTEGER: d2i_ASN1_INTEGER returns nil
            local _, v2, err2 = asn1.decode(ldap_hex("02 00"))
            assert(v2 == nil, "no value for zero-len INTEGER")
            assert(err2 ~= nil, "zero-len INTEGER reports error")

            -- zero-length ENUMERATED: d2i_ASN1_ENUMERATED returns nil
            local _, v3, err3 = asn1.decode(ldap_hex("0a 00"))
            assert(v3 == nil, "no value for zero-len ENUMERATED")
            assert(err3 ~= nil, "zero-len ENUMERATED reports error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: constructed OCTET STRING (0x24) is rejected (BER smuggling)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- constructed OCTET STRING: inner TLVs must not be handed back (RFC 4511 s5.1)
            local _, v, err = asn1.decode(ldap_hex("24 07 04 02 41 42 04 01 43"))
            assert(v == nil, "constructed OCTET STRING yields no value")
            assert(err ~= nil, "constructed OCTET STRING reports error")

            -- primitive OCTET STRING still decodes normally
            local _, v2 = asn1.decode(ldap_hex("04 02 41 42"))
            assert(v2 == "AB", "primitive OCTET STRING still works")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: put_object length header is not truncated at 0x00 length octets
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            -- long-form length octets containing 0x00 (256, 512) must round-trip
            for _, n in ipairs({0, 1, 255, 256, 512, 768}) do
                local data = string.rep("A", n)
                local enc = asn1.put_object(asn1.TAG.SEQUENCE, asn1.CLASS.UNIVERSAL, 1, data)
                local obj = assert(asn1.get_object(enc), "n=" .. n .. " failed to parse")
                assert(obj.len == n, "n=" .. n .. " decoded len " .. tostring(obj.len))
                assert(#enc == obj.hl + n, "n=" .. n .. " total length mismatch")
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

=== TEST 8: a child TLV may not overrun its parent's declared length
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- outer SEQUENCE says 3 bytes, inner OCTET STRING claims 5, buffer long enough
            local _, v, err = asn1.decode(ldap_hex("30 03 04 05 41 42 43 44 45"))
            assert(v == nil, "no value when a child overruns its parent")
            assert(err ~= nil, "parent overrun reports an error")

            -- same bytes, correct outer length
            local _, ok_v = asn1.decode(ldap_hex("30 07 04 05 41 42 43 44 45"))
            assert(type(ok_v) == "table" and ok_v[1] == "ABCDE", "well-formed still decodes")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
