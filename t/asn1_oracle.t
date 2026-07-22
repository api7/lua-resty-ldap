# Go go1.26.3 encoding/asn1 (differential oracle): https://github.com/golang/go/blob/go1.26.3/src/encoding/asn1/asn1_test.go
# pyasn1 v0.6.4: https://github.com/pyasn1/pyasn1/blob/v0.6.4/tests/codec/ber/test_decoder.py

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

=== TEST 1: INTEGER is exact or rejected, never silently rounded or wrapped
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- 2^53+1 = 9007199254740993; ASN1_INTEGER_get double-rounds to 9007199254740992.
            local _, v1, e1 = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 01"))
            assert(e1 ~= nil, "2^53+1 must be rejected, got " .. tostring(v1))
            assert(v1 ~= 9007199254740992, "2^53+1 must not round to 2^53")

            -- -(2^53+1)
            local _, v2, e2 = asn1.decode(ldap_hex("02 07 df ff ff ff ff ff ff"))
            assert(e2 ~= nil, "-(2^53+1) must be rejected, got " .. tostring(v2))

            -- 2^63-1 = 9223372036854775807, rounds up to ...808 as a double
            local _, v3, e3 = asn1.decode(ldap_hex("02 08 7f ff ff ff ff ff ff ff"))
            assert(e3 ~= nil, "2^63-1 must be rejected, got " .. tostring(v3))

            local _, v4, e4 = asn1.decode(ldap_hex("02 09 00 ff ff ff ff ff ff ff ff"))
            assert(v4 ~= -1, "2^64-1 must not decode as -1")
            assert(e4 ~= nil, "2^64-1 must be rejected, got " .. tostring(v4))

            -- 20-byte INTEGER also overflows to -1 today
            local _, v5, e5 = asn1.decode(ldap_hex("02 14 00 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"))
            assert(v5 ~= -1, "160-bit INTEGER must not decode as -1")
            assert(e5 ~= nil, "160-bit INTEGER must be rejected")

            -- Exactly-representable values keep working; last is RFC 4511 s4.1.1 maxInt (messageID bound).
            local _, ok1 = asn1.decode(ldap_hex("02 01 ff"))
            assert(ok1 == -1, "genuine -1 still decodes, got " .. tostring(ok1))
            local _, ok2 = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 00"))
            assert(ok2 == 9007199254740992, "2^53 exact, got " .. tostring(ok2))
            local _, ok3 = asn1.decode(ldap_hex("02 05 01 00 00 00 00"))
            assert(ok3 == 4294967296, "2^32 exact, got " .. tostring(ok3))
            local _, ok4 = asn1.decode(ldap_hex("02 04 7f ff ff ff"))
            assert(ok4 == 2147483647, "maxInt messageID exact, got " .. tostring(ok4))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: high-tag-number identifier octets are not an alias for a low tag
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local aliases = {
                "1f 04 03 41 42 43",          -- high-tag form for tag 4
                "1f 80 04 03 41 42 43",       -- + one 0x80 padding octet
                "1f 80 80 04 03 41 42 43",    -- + two
                "1f 80 80 80 04 03 41 42 43", -- + three
            }
            for _, hex in ipairs(aliases) do
                local _, v, err = asn1.decode(ldap_hex(hex))
                assert(v ~= "ABC", "alias " .. hex .. " must not decode as OCTET STRING ABC")
                assert(err ~= nil, "alias " .. hex .. " must report an error")
            end

            -- same trick on SEQUENCE: 3f 10 aliases 30
            local _, sv, serr = asn1.decode(ldap_hex("3f 10 03 02 01 05"))
            assert(type(sv) ~= "table", "3f 10 must not decode as a SEQUENCE")
            assert(serr ~= nil, "3f 10 must report an error")

            -- and with a class bit set: 9f 04 aliases context [4]
            local _, cv, cerr = asn1.decode(ldap_hex("9f 04 03 41 42 43"))
            assert(cv ~= "ABC", "9f 04 must not decode as OCTET STRING ABC")
            assert(cerr ~= nil, "9f 04 must report an error")

            -- canonical encodings are untouched
            local _, good = asn1.decode(ldap_hex("04 03 41 42 43"))
            assert(good == "ABC", "canonical OCTET STRING still decodes")
            local _, goodseq = asn1.decode(ldap_hex("30 03 02 01 05"))
            assert(type(goodseq) == "table" and goodseq[1] == 5, "canonical SEQUENCE still decodes")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: a non-canonical tag cannot impersonate the LDAPMessage envelope
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(
                ldap_hex("3f 10 0c 02 01 01 61 07 0a 01 00 04 00 04 00"))
            assert(bad == nil, "high-tag-aliased envelope must be rejected")
            assert(err ~= nil, "high-tag-aliased envelope must report an error")

            -- the canonical form of the same message still parses
            local ok = assert(protocol.decode_message(
                ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(ok.result_code == 0, "canonical BindResponse still parses")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: a malformed attribute type returns an error, never an uncaught Lua exception
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local cases = {
                "30 10 02 01 03 64 0b 04 01 78 30 06 30 04 05 00 31 00",  -- type = NULL
                "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 01 01 ff 31 00", -- type = BOOLEAN
            }
            for _, hex in ipairs(cases) do
                local pok, res, err = pcall(protocol.decode_message, ldap_hex(hex))
                assert(pok, "must not raise: " .. hex .. " -> " .. tostring(res))
                assert(res == nil, "must not return a result for " .. hex)
                assert(err ~= nil, "must report an error for " .. hex)
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

=== TEST 5: LDAPMessage fields are type-checked, not just structurally decoded
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- objectName is an INTEGER -> entry_dn becomes the number 5
            local b1, e1 = protocol.decode_message(
                ldap_hex("30 11 02 01 03 64 0c 02 01 05 30 07 30 05 04 01 73 31 00"))
            assert(b1 == nil, "non-string objectName must be rejected, got entry_dn=" ..
                              tostring(b1 and b1.entry_dn))
            assert(e1 ~= nil, "non-string objectName must report an error")

            -- attribute type is an INTEGER -> attributes[5], a numeric key
            local b2, e2 = protocol.decode_message(
                ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 30 05 02 01 05 31 00"))
            assert(b2 == nil, "non-string attribute type must be rejected")
            assert(e2 ~= nil, "non-string attribute type must report an error")

            -- attribute type is a SEQUENCE -> attributes[<table>], an unlookupable key
            local b3, e3 = protocol.decode_message(
                ldap_hex("30 10 02 01 03 64 0b 04 01 78 30 06 30 04 30 00 31 00"))
            assert(b3 == nil, "table-valued attribute type must be rejected")
            assert(e3 ~= nil, "table-valued attribute type must report an error")

            -- messageID is an OCTET STRING -> message_id becomes a string
            local b4, e4 = protocol.decode_message(
                ldap_hex("30 0c 04 01 01 61 07 0a 01 00 04 00 04 00"))
            assert(b4 == nil, "non-integer messageID must be rejected, got " ..
                              type(b4 and b4.message_id))
            assert(e4 ~= nil, "non-integer messageID must report an error")

            -- a well-formed entry is unaffected
            local ok = assert(protocol.decode_message(
                ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(ok.entry_dn == "x", "well-formed entry_dn")
            assert(type(ok.attributes.s) == "table", "well-formed attribute key")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: SearchResultReference URI list never silently shrinks
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(ldap_hex("30 0a 02 01 02 73 05 04 01 78 05 00"))
            if bad then
                assert(false, "undecodable referral element must not be dropped, #uris=" ..
                              tostring(#bad.uris))
            end
            assert(err ~= nil, "undecodable referral element must report an error")

            -- a genuine two-URI referral is unaffected
            local ok = assert(protocol.decode_message(
                ldap_hex("30 0e 02 01 02 73 09 04 01 78 04 04 6c 64 61 70")))
            assert(#ok.uris == 2, "two URIs, got " .. #ok.uris)
            assert(ok.uris[1] == "x" and ok.uris[2] == "ldap", "URI values")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: differential agreements that must keep holding
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, l1 = asn1.decode(ldap_hex("04 81 03 41 42 43"))
            assert(l1 == "ABC", "81-form length still accepted")
            local _, l2 = asn1.decode(ldap_hex("04 82 00 03 41 42 43"))
            assert(l2 == "ABC", "82-form length still accepted")
            local _, l3 = asn1.decode(ldap_hex("04 84 00 00 00 03 41 42 43"))
            assert(l3 == "ABC", "84-form length still accepted")
            local _, l4 = asn1.decode(ldap_hex("30 81 05 04 03 41 42 43"))
            assert(type(l4) == "table" and l4[1] == "ABC", "non-minimal SEQUENCE length accepted")

            -- indefinite length stays rejected; RFC 4511 s5.1 restricts LDAP to definite-length (Go agrees).
            local _, i1, ierr = asn1.decode(ldap_hex("30 80 04 03 41 42 43 00 00"))
            assert(i1 == nil and ierr ~= nil, "indefinite length rejected")

            local _, c1, cerr = asn1.decode(ldap_hex("24 07 04 02 41 42 04 01 43"))
            assert(c1 == nil and cerr ~= nil, "constructed OCTET STRING rejected")

            -- binary payloads round-trip byte-exactly (matches the oracle).
            local _, b1 = asn1.decode(ldap_hex("04 04 ff fe 00 80"))
            assert(b1 == "\255\254\0\128", "high bytes and NUL preserved")

            local function der_len(n)
                if n < 128 then return string.char(n) end
                local b = ""
                while n > 0 do b = string.char(n % 256) .. b; n = math.floor(n / 256) end
                return string.char(0x80 + #b) .. b
            end
            local deep = ""
            for _ = 1, 400 do deep = "\48" .. der_len(#deep) .. deep end
            local pok, _, dv, derr = pcall(asn1.decode, deep)
            assert(pok, "deep nesting must not raise")
            assert(dv == nil and derr ~= nil, "deep nesting rejected with an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
