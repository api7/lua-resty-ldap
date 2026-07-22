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

=== TEST 1: rasn BER decoder `sequence()` vector must not silently vanish
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, v, err = asn1.decode(ldap_hex("30 0a 16 05 53 6d 69 74 68 01 01 ff"))
            assert(err ~= nil,
                   "SEQUENCE with undecodable members must report an error, got value=" ..
                   tostring(v) .. " n=" .. (type(v) == "table" and #v or -1))
            assert(v == nil, "no partial value alongside the error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: pyasn1 Sequence/Set DefMode vectors must not shrink and re-index
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, seq, err = asn1.decode(
                ldap_hex("30 12 05 00 04 0b 71 75 69 63 6b 20 62 72 6f 77 6e 02 01 01"))
            assert(err ~= nil,
                   "SEQUENCE containing NULL must error rather than silently shrink; got n=" ..
                   (type(seq) == "table" and #seq or -1))
            assert(seq == nil, "no partial array alongside the error")

            local _, set, err2 = asn1.decode(
                ldap_hex("31 12 05 00 04 0b 71 75 69 63 6b 20 62 72 6f 77 6e 02 01 01"))
            assert(err2 ~= nil, "SET containing NULL must error rather than silently shrink")
            assert(set == nil, "no partial array alongside the error")

            local _, mix, err3 = asn1.decode(ldap_hex("30 09 02 01 01 01 01 ff 02 01 02"))
            assert(err3 ~= nil, "undecodable middle member must error, not re-index the array")
            assert(mix == nil, "no partial array alongside the error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: 9-byte INTEGER overflow must not be reported as -1
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, pos_long, err = asn1.decode(ldap_hex("02 09 00 ff ff ff ff ff ff ff ff"))
            assert(err ~= nil,
                   "INTEGER exceeding the representable range must error; got " ..
                   tostring(pos_long))
            assert(pos_long ~= -1, "overflow must never be indistinguishable from -1")

            local _, neg_long, err2 = asn1.decode(ldap_hex("02 09 ff 00 00 00 00 00 00 00 01"))
            assert(err2 ~= nil, "negative INTEGER overflow must error; got " .. tostring(neg_long))
            assert(neg_long ~= -1, "overflow must never be indistinguishable from -1")

            local _, go_of, err3 = asn1.decode(ldap_hex("02 09 80 00 00 00 00 00 00 00 00"))
            assert(err3 ~= nil, "9-byte INTEGER must error; got " .. tostring(go_of))

            -- The genuine -1 must keep working, so the fix cannot just blanket-ban -1.
            local _, minus_one, err4 = asn1.decode(ldap_hex("02 01 ff"))
            assert(err4 == nil and minus_one == -1, "a real -1 must still decode as -1")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: tags with no decoder must error, never return a silent nil
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

=== TEST 5: dispatch must match tag CLASS, not just tag number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- decode() dispatches on obj.tag alone, so non-universal tags alias universal types.

            local _, ctx4, e1 = asn1.decode(ldap_hex("84 03 61 62 63"))
            assert(e1 ~= nil, "context-specific [4] must not decode as OCTET STRING; got " ..
                              tostring(ctx4))
            assert(ctx4 ~= "abc", "context [4] must not alias universal OCTET STRING")

            local _, priv4, e2 = asn1.decode(ldap_hex("c4 03 61 62 63"))
            assert(e2 ~= nil, "private [4] must not decode as OCTET STRING; got " .. tostring(priv4))

            -- Context [16] / [17] constructed get walked as SEQUENCE / SET.
            local _, ctx16, e3 = asn1.decode(ldap_hex("b0 03 02 01 05"))
            assert(e3 ~= nil, "context [16] must not be walked as SEQUENCE")
            assert(ctx16 == nil, "context [16] must not yield a member array")
            local _, ctx17, e4 = asn1.decode(ldap_hex("b1 03 02 01 05"))
            assert(e4 ~= nil, "context [17] must not be walked as SET")
            assert(ctx17 == nil, "context [17] must not yield a member array")

            -- APPLICATION [16] -- i.e. an LDAP protocolOp -- likewise.
            local _, app16, e5 = asn1.decode(ldap_hex("70 03 02 01 05"))
            assert(e5 ~= nil, "APPLICATION [16] must not be walked as SEQUENCE")
            assert(app16 == nil, "APPLICATION [16] must not yield a member array")

            local _, tb, e6 = asn1.decode(ldap_hex("a2 03 01 01 ff"))
            assert(tb == nil, "context [2] constructed must not yield a value")
            assert(e6 ~= nil, "context [2] constructed must report an error")
            assert(not e6:find("INTEGER"),
                   "error for a context-specific tag must not blame INTEGER, got: " .. e6)

            local _, exp, e7 = asn1.decode(
                ldap_hex("65 11 04 0f 51 75 69 63 6b 20 62 72 6f 77 6e 20 66 6f 78"))
            assert(e7 ~= nil, "APPLICATION [5] must report an error, not a silent nil")
            assert(exp == nil, "APPLICATION [5] must not yield a value")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: SEQUENCE/SET decoders must honour the constructed bit
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, prim_seq, e1 = asn1.decode(ldap_hex("10 03 02 01 05"))
            assert(e1 ~= nil, "primitive universal tag 16 must be rejected, not walked as SEQUENCE")
            assert(prim_seq == nil, "primitive tag 16 must not yield a member array")

            local _, prim_set, e2 = asn1.decode(ldap_hex("11 03 02 01 05"))
            assert(e2 ~= nil, "primitive universal tag 17 must be rejected, not walked as SET")
            assert(prim_set == nil, "primitive tag 17 must not yield a member array")

            -- A properly constructed SEQUENCE of the same content still decodes.
            local _, good, e3 = asn1.decode(ldap_hex("30 03 02 01 05"))
            assert(e3 == nil and type(good) == "table" and good[1] == 5,
                   "constructed SEQUENCE still decodes")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: ported vectors that must KEEP working (BER leniency preserved)
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

=== TEST 8: LDAPMessage envelope must consume the whole packet
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local base = "30 0c 02 01 01 61 07 0a 01 00 04 00 04 00"

            local ok_res = assert(protocol.decode_message(ldap_hex(base)), "clean packet still decodes")
            assert(ok_res.result_code == 0, "clean packet result_code")

            local r1, e1 = protocol.decode_message(ldap_hex(base .. " de ad be ef"))
            assert(r1 == nil, "trailing garbage after the envelope must be rejected")
            assert(e1 ~= nil, "trailing garbage must report an error")

            -- A whole second LDAPMessage appended: today only the first is seen.
            local r2, e2 = protocol.decode_message(
                ldap_hex(base .. " 30 0c 02 01 02 61 07 0a 01 31 04 00 04 00"))
            assert(r2 == nil, "a second appended LDAPMessage must be rejected")
            assert(e2 ~= nil, "a second appended LDAPMessage must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 9: silent-nil fields must not reach protocol.lua as nil
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- (a) PartialAttribute type NULL not OCTET STRING: atype nil -> attributes[nil] error.
            local entry = "30 10 02 01 03 64 0b 04 01 78 30 06 30 04 05 00 31 00"
            local called, res, err = pcall(protocol.decode_message, ldap_hex(entry))
            assert(called, "decode_message must not raise a Lua error, got: " .. tostring(res))
            assert(res == nil and err ~= nil,
                   "an unreadable attribute type must be a returned error")

            -- (b) resultCode BOOLEAN not ENUMERATED: result_code nil -> ldap.lua concat error.
            local bad_code = "30 0c 02 01 01 61 07 01 01 ff 04 00 04 00"
            local r2, e2 = protocol.decode_message(ldap_hex(bad_code))
            assert(r2 == nil, "a non-ENUMERATED resultCode must be rejected, got a result table")
            assert(e2 ~= nil, "a non-ENUMERATED resultCode must report an error")

            -- (c) objectName NULL not OCTET STRING: entry_dn silently becomes nil.
            local bad_dn = "30 0f 02 01 03 64 0a 05 00 30 06 30 04 04 00 31 00"
            local r3, e3 = protocol.decode_message(ldap_hex(bad_dn))
            assert(r3 == nil, "an unreadable objectName must be rejected, got entry_dn=" ..
                              tostring(r3 and r3.entry_dn))
            assert(e3 ~= nil, "an unreadable objectName must report an error")

            -- (d) SearchResultReference with an undecodable element: URI list silently shrinks.
            local bad_ref = "30 0c 02 01 02 73 07 04 03 61 62 63 05 00"
            local r4, e4 = protocol.decode_message(ldap_hex(bad_ref))
            assert(r4 == nil, "an unreadable referral URI must be rejected, got n=" ..
                              tostring(r4 and r4.uris and #r4.uris))
            assert(e4 ~= nil, "an unreadable referral URI must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 10: INTEGER beyond 2^53 must not be silently rounded
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, a, ea = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 00"))
            local _, b, eb = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 01"))
            assert(eb ~= nil or a ~= b,
                   "2^53 and 2^53+1 must not both decode to " .. string.format("%.17g", tonumber(b) or 0))

            local _, mx, emx = asn1.decode(ldap_hex("02 08 7f ff ff ff ff ff ff ff"))
            assert(emx ~= nil or mx == 9223372036854775807,
                   "maxint64 must be exact or refused, got " .. string.format("%.17g", tonumber(mx) or 0))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
