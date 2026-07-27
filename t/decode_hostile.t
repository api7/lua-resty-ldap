# Vectors cross-checked against pyasn1 v0.6.4 and rasn v0.6.1.
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

=== TEST 1: bytes after the LDAPMessage envelope must be rejected, not ignored
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local r1, e1 = protocol.decode_message(ldap_hex(
                "30 0c 02 01 02 61 07 0a 01 00 04 00 04 00 de ad be ef"))
            assert(r1 == nil, "trailing garbage after envelope must be rejected")
            assert(e1 ~= nil, "trailing garbage after envelope must report an error")

            -- Two LDAPMessages in one buffer: forged success consumed, genuine reply dropped.
            local r2, e2 = protocol.decode_message(ldap_hex(
                "30 0c 02 01 02 61 07 0a 01 00 04 00 04 00" ..
                "30 0c 02 01 01 61 07 0a 01 31 04 00 04 00"))
            assert(r2 == nil, "appended second LDAPMessage must be rejected")
            assert(e2 ~= nil, "appended second LDAPMessage must report an error")

            -- The exact-fit packet is unaffected.
            local ok = assert(protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(ok.result_code == 0, "well-formed packet still decodes")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: a second APPLICATION protocolOp inside the envelope must be rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local r, e = protocol.decode_message(ldap_hex(
                "30 15 02 01 01 61 07 0a 01 31 04 00 04 00 61 07 0a 01 00 04 00 04 00"))
            assert(r == nil, "second APPLICATION protocolOp must be rejected")
            assert(e ~= nil, "second APPLICATION protocolOp must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: attribute values are always an array, never a bare string
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local pkt = ldap_hex("30 21 02 01 03 64 1c 04 01 78 30 17 30 15" ..
                          "04 08 6d 65 6d 62 65 72 4f 66" ..
                          "04 09 63 6e 3d 61 64 6d 69 6e 73")
            local r, e = protocol.decode_message(pkt)
            assert(r == nil, "non-SET vals must be rejected")
            assert(e ~= nil, "non-SET vals must report an error")

            -- Well-formed SET OF still yields an array.
            local good = assert(protocol.decode_message(ldap_hex(
                "30 23 02 01 03 64 1e 04 01 78 30 19 30 17" ..
                "04 08 6d 65 6d 62 65 72 4f 66" ..
                "31 0b 04 09 63 6e 3d 61 64 6d 69 6e 73")))
            assert(type(good.attributes.memberOf) == "table", "vals is an array")
            assert(good.attributes.memberOf[1] == "cn=admins", "vals content")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: a duplicate attribute type is decoded, not treated as a protocol error
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- PartialAttributeList: memberOf={"cn=admins"} followed by memberOf={}.
            local pkt = ldap_hex("30 31 02 01 03 64 2c 04 01 78 30 27" ..
                          "30 17 04 08 6d 65 6d 62 65 72 4f 66 31 0b 04 09 63 6e 3d 61 64 6d 69 6e 73" ..
                          "30 0c 04 08 6d 65 6d 62 65 72 4f 66 31 00")
            local r, e = protocol.decode_message(pkt)
            assert(r ~= nil, "duplicate attribute type must decode: " .. tostring(e))
            assert(type(r.attributes.memberOf) == "table",
                   "memberOf must still be an array, got " .. type(r.attributes.memberOf))
            for k in pairs(r.attributes) do
                assert(type(k) == "string", "attribute key is a " .. type(k))
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

=== TEST 5: an undecodable SET/SEQUENCE member must error, not shrink the array
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local cases = {
                { "vals with EOC member",
                  "30 20 02 01 03 64 1b 04 01 78 30 16 30 14" ..
                  "04 08 6d 65 6d 62 65 72 4f 66 31 08 04 01 61 00 00 04 01 62" },
                { "vals with BOOLEAN member",
                  "30 21 02 01 03 64 1c 04 01 78 30 17 30 15" ..
                  "04 08 6d 65 6d 62 65 72 4f 66 31 09 04 01 61 01 01 ff 04 01 62" },
                { "SearchResRef with BOOLEAN member",
                  "30 0e 02 01 02 73 09 04 01 61 01 01 ff 04 01 62" },
                { "SearchResRef with EOC member",
                  "30 0d 02 01 02 73 08 04 01 61 00 00 04 01 62" },
            }
            for _, c in ipairs(cases) do
                local r, e = protocol.decode_message(ldap_hex(c[2]))
                assert(r == nil, c[1] .. " must be rejected, got a result")
                assert(e ~= nil, c[1] .. " must report an error")
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

=== TEST 6: constructed OCTET STRING (0x24) is rejected at every nesting level
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local cases = {
                { "matchedDN",       "30 13 02 01 01 61 0e 0a 01 31 24 07 04 02 41 42 04 01 43 04 00" },
                { "diagnosticMsg",   "30 10 02 01 01 61 0b 0a 01 31 04 00 24 04 04 02 41 42" },
                { "objectName",      "30 10 02 01 03 64 0b 24 07 04 02 41 42 04 01 43 30 00" },
                { "attribute value", "30 17 02 01 03 64 12 04 01 78 30 0d 30 0b 04 01 6d 31 06 24 04 04 02 41 42" },
                { "SearchResRef URI","30 0a 02 01 02 73 05 24 03 04 01 61" },
            }
            for _, c in ipairs(cases) do
                local r, e = protocol.decode_message(ldap_hex(c[2]))
                assert(r == nil, c[1] .. ": constructed OCTET STRING must be rejected")
                assert(e ~= nil, c[1] .. ": constructed OCTET STRING must report an error")
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

=== TEST 7: PartialAttributeList / PartialAttribute containers must be SEQUENCEs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local cases = {
                { "PartialAttributeList as SET",
                  "30 14 02 01 03 64 0f 04 01 78 31 0a 30 08 04 01 6d 31 03 04 01 76" },
                { "PartialAttribute as CONTEXT [16]",
                  "30 14 02 01 03 64 0f 04 01 78 30 0a b0 08 04 01 6d 31 03 04 01 76" },
                { "primitive APPLICATION protocolOp",
                  "30 0c 02 01 01 41 07 0a 01 00 04 00 04 00" },
            }
            for _, c in ipairs(cases) do
                local r, e = protocol.decode_message(ldap_hex(c[2]))
                assert(r == nil, c[1] .. " must be rejected, got a result")
                assert(e ~= nil, c[1] .. " must report an error")
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

=== TEST 8: truncation and byte-flip sweep never raises a Lua exception
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local pkt = ldap_hex("30 12 02 01 01 61 0d 0a 01 00 04 04 64 63 3d 78 04 02 68 69")
            assert(#pkt == 20, "packet length " .. #pkt)
            local base = assert(protocol.decode_message(pkt))
            assert(base.result_code == 0 and base.matched_dn == "dc=x", "baseline")

            -- Every proper prefix must fail cleanly.
            for k = 0, #pkt - 1 do
                local pok, r, e = pcall(protocol.decode_message, pkt:sub(1, k))
                assert(pok, "truncation at " .. k .. " raised: " .. tostring(r))
                assert(r == nil, "truncation at " .. k .. " decoded to a result")
                assert(e ~= nil, "truncation at " .. k .. " returned nil with no error")
            end

            -- Single-byte corruption must never escape as an exception.
            local flips = { 0x00, 0x01, 0x24, 0x30, 0x7f, 0x80, 0x84, 0xff }
            for i = 1, #pkt do
                for _, b in ipairs(flips) do
                    local m = pkt:sub(1, i - 1) .. string.char(b) .. pkt:sub(i + 1)
                    local pok, r, e = pcall(protocol.decode_message, m)
                    assert(pok, string.format("byte %d -> %02x raised: %s", i, b, tostring(r)))
                    assert(r ~= nil or e ~= nil,
                           string.format("byte %d -> %02x returned nil with no error", i, b))
                end
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

=== TEST 9: BER leniency and hard limits are preserved
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local _, v = asn1.decode(ldap_hex("04 81 03 41 42 43"))
            assert(v == "ABC", "non-minimal length must still decode, got " .. tostring(v))
            local _, v2 = asn1.decode(ldap_hex("04 83 00 00 03 41 42 43"))
            assert(v2 == "ABC", "3-octet non-minimal length must still decode, got " .. tostring(v2))
            -- matchedDN "dc=x" and diagnosticMessage "hi" with long-form lengths
            local ok = assert(protocol.decode_message(ldap_hex(
                "30 14 02 01 01 61 0f 0a 01 00 04 81 04 64 63 3d 78 04 81 02 68 69")))
            assert(ok.result_code == 0, "non-minimal LDAPMessage result_code")
            assert(ok.matched_dn == "dc=x" and ok.diagnostic_msg == "hi",
                   "non-minimal LDAPMessage fields")
            -- long-form envelope and protocolOp headers
            local ok2 = assert(protocol.decode_message(ldap_hex(
                "30 81 13 02 01 01 61 81 0d 0a 01 00 04 04 64 63 3d 78 04 02 68 69")))
            assert(ok2.result_code == 0 and ok2.matched_dn == "dc=x",
                   "long-form envelope/protocolOp headers decode")

            local rejected = {
                { "indefinite length", "30 80 02 01 01 61 07 0a 01 00 04 00 04 00 00 00" },
                { "length 84 ffffffff", "30 84 ff ff ff ff 02 01 01" },
                { "length 88 (8 octets)", "30 88 ff ff ff ff ff ff ff ff 02 01 01" },
                { "empty buffer", "" },
                { "envelope of length 0", "30 00" },
            }
            for _, c in ipairs(rejected) do
                local r, e = protocol.decode_message(ldap_hex(c[2]))
                assert(r == nil and e ~= nil, c[1] .. " must be rejected")
            end

            local function enclen(n)
                if n < 128 then return string.char(n) end
                local out = ""
                while n > 0 do out = string.char(n % 256) .. out; n = math.floor(n / 256) end
                return string.char(0x80 + #out) .. out
            end
            local deep = ldap_hex("04 01 41")
            for _ = 1, 500 do deep = "\48" .. enclen(#deep) .. deep end
            local pok, _, dv, derr = pcall(asn1.decode, deep)
            assert(pok, "deep nesting raised: " .. tostring(dv))
            assert(dv == nil and derr ~= nil, "deep nesting must be refused")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 10: regression guard -- genuinely empty SETs stay empty, not errors
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- typesOnly zero-member vals SET (31 00) must stay empty, not become an error
            local res = assert(protocol.decode_message(ldap_hex(
                "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(type(res.attributes.s) == "table", "s is an array")
            assert(#res.attributes.s == 0, "s is empty, not an error")

            -- And a well-formed multi-valued SET still returns every member.
            local res2 = assert(protocol.decode_message(ldap_hex(
                "30 1e 02 01 03 64 19 04 01 78 30 14 30 12 04 08 6d 65 6d 62 65 72 4f 66" ..
                " 31 06 04 01 61 04 01 62")))
            assert(#res2.attributes.memberOf == 2, "both members returned")
            assert(res2.attributes.memberOf[1] == "a", "member 1")
            assert(res2.attributes.memberOf[2] == "b", "member 2")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 11: every AttributeValue must be an OCTET STRING
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- rasn dropped the whole attribute here; the pure-Lua decoder used to
            -- store the value, leaking a number or a table into a string array
            local cases = {
                { "INTEGER value",
                  "30 14 02 01 03 64 0f 04 01 78 30 0a 30 08 04 01 73 31 03 02 01 05" },
                { "ENUMERATED value",
                  "30 14 02 01 03 64 0f 04 01 78 30 0a 30 08 04 01 73 31 03 0a 01 07" },
                { "SEQUENCE value",
                  "30 13 02 01 03 64 0e 04 01 78 30 09 30 07 04 01 73 31 02 30 00" },
                { "nested SET value",
                  "30 16 02 01 03 64 11 04 01 78 30 0c 30 0a 04 01 73 31 05 31 03 04 01 41" },
                { "one good value then an INTEGER",
                  "30 17 02 01 03 64 12 04 01 78 30 0d 30 0b 04 01 73 31 06 04 01 41 02 01 05" },
            }

            local leaks = {}
            for _, c in ipairs(cases) do
                local pok, res, err = pcall(protocol.decode_message, ldap_hex(c[2]))
                if not pok then
                    table.insert(leaks, c[1] .. " RAISED: " .. tostring(res))
                elseif res ~= nil then
                    table.insert(leaks, string.format("%s accepted (vals[1] is a %s)",
                        c[1], type(res.attributes and res.attributes.s
                                   and res.attributes.s[1])))
                elseif err == nil then
                    table.insert(leaks, c[1] .. " returned nil with no error")
                end
            end
            if #leaks > 0 then
                ngx.say(#leaks .. " non-OCTET-STRING values accepted:")
                ngx.say(table.concat(leaks, "\n"))
                return
            end

            -- the tightened check must not cost BER leniency
            local lenient = assert(protocol.decode_message(ldap_hex(
                "30 17 02 01 03 64 12 04 01 78 30 0d 30 0b 04 01 73 31 06 04 81 03 41 42 43")))
            assert(lenient.attributes.s[1] == "ABC", "non-minimal length still decodes")

            -- and well-formed entries are untouched
            local ok = assert(protocol.decode_message(ldap_hex(
                "30 14 02 01 03 64 0f 04 01 78 30 0a 30 08 04 01 73 31 03 04 01 41")))
            assert(ok.attributes.s[1] == "A", "single value")
            local empty = assert(protocol.decode_message(ldap_hex(
                "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(#empty.attributes.s == 0, "typesOnly empty SET stays an empty array")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
