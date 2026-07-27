# Test vectors: pyasn1 v0.6.4 (LengthFieldLimit, NestingDepthLimit); Go encoding/asn1.

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

=== TEST 1: degenerate [start, stop) regions are rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local d = ldap_hex("04 03 41 42 43")   -- 5 bytes

            -- empty region: start == stop
            local o, e = asn1.get_object(d, 0, 0)
            assert(o == nil and e ~= nil, "start==stop must error")
            local o2, e2 = asn1.get_object(d, 3, 3)
            assert(o2 == nil and e2 ~= nil, "start==stop mid-buffer must error")

            -- inverted region: start > stop
            local o3, e3 = asn1.get_object(d, 4, 2)
            assert(o3 == nil and e3 ~= nil, "start>stop must error")

            -- stop past the end of the buffer
            local o4, e4 = asn1.get_object(d, 0, 99)
            assert(o4 == nil and e4 ~= nil, "stop>#der must error")

            -- start at/past the end of the buffer
            local o5, e5 = asn1.get_object(d, 5)
            assert(o5 == nil and e5 ~= nil, "start==#der must error")
            local o6, e6 = asn1.get_object(d, 6)
            assert(o6 == nil and e6 ~= nil, "start>#der must error")

            -- empty buffer
            local o7, e7 = asn1.get_object("")
            assert(o7 == nil and e7 ~= nil, "empty der must error")
            local n8, v8, e8 = asn1.decode("")
            assert(v8 == nil and e8 ~= nil, "decode('') must error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: a negative start is rejected, never read out of bounds
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- guard at asn1.lua:187 has no lower bound; negative start reads before payload
            for _, hex in ipairs({"04 03 41 42 43", "30 06 04 01 41 04 01 42",
                                  "30 0c 02 01 01 61 07 0a 01 00 04 00 04 00"}) do
                local d = ldap_hex(hex)
                for s = -8, -1 do
                    local o, e = asn1.get_object(d, s)
                    assert(o == nil, "get_object must reject start=" .. s ..
                           " (returned tag=" .. tostring(o and o.tag) ..
                           " len=" .. tostring(o and o.len) ..
                           " offset=" .. tostring(o and o.offset) .. ")")
                    assert(e ~= nil, "negative start must report an error, s=" .. s)
                end
            end

            -- decode() must refuse too, and never return a negative next-offset
            local d = ldap_hex("30 06 04 01 41 04 01 42")
            for s = -8, -1 do
                local n, v, e = asn1.decode(d, s)
                assert(e ~= nil, "decode must error on start=" .. s ..
                       " (got next=" .. tostring(n) .. ")")
                assert(n == nil or n >= 0, "decode must not return a negative offset, s=" .. s)
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

=== TEST 3: non-integer offsets are rejected; hl is always a whole number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- fractional start escapes with hl = 1.5, corrupting d2i decoding
            local d = ldap_hex("04 02 41 42 43")
            local o, e = asn1.get_object(d, 0.5)
            assert(o == nil, "fractional start must be rejected (got hl=" ..
                   tostring(o and o.hl) .. ")")
            assert(e ~= nil, "fractional start must report an error")

            local ds, es = asn1.get_object(d, 0, 4.5)
            assert(ds == nil and es ~= nil, "fractional stop must be rejected")

            -- same INTEGER decodes to 5 at start 0 but fails at start 0.5 (hl+len truncated)
            local di = ldap_hex("02 01 05 41 42")
            local _, v0 = asn1.decode(di, 0)
            assert(v0 == 5, "INTEGER at start 0 is 5, got " .. tostring(v0))
            local _, vf, ef = asn1.decode(di, 0.5)
            assert(ef ~= nil, "fractional start must error, not silently mis-decode")

            -- fractional start at a NONZERO offset where flooring would land on a valid TLV:
            -- rejection must be pinned, not left to a downstream parse error
            local der2 = ldap_hex("41 04 03 41 42 43 00 00 00 00")
            local og, eg = asn1.get_object(der2, 1.9, #der2)
            assert(og == nil, "fractional start 1.9 must be rejected, not floored onto the TLV at 1"
                              .. (og and (" (got hl=" .. tostring(og.hl) .. ")") or ""))
            assert(eg ~= nil, "fractional start 1.9 must report an error")
            local _, vg, dg = asn1.decode(der2, 1.2)
            assert(vg == nil and dg ~= nil,
                   "decode must reject fractional offset 1.2 instead of silently flooring it")

            -- whenever get_object succeeds, every reported offset must be integral
            local buffers = {
                ldap_hex("04 03 41 42 43"),
                ldap_hex("30 81 82") .. string.rep("\0", 130),
                ldap_hex("04 81 03 41 42 43"),
            }
            for i, buf in ipairs(buffers) do
                local ok = assert(asn1.get_object(buf), "buffer " .. i)
                assert(ok.hl % 1 == 0, "hl must be integral, got " .. tostring(ok.hl))
                assert(ok.offset % 1 == 0, "offset must be integral")
                assert(ok.len % 1 == 0, "len must be integral")
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

=== TEST 4: zero-length content and content ending exactly at the buffer end
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- string_sub with len == 0 must yield "", not a slice from the end
            local n, v, e = asn1.decode(ldap_hex("04 00"))
            assert(e == nil, "zero-length OCTET STRING must decode")
            assert(v == "", "zero-length value must be empty string, got " .. tostring(v))
            assert(n == 2, "next offset must be 2, got " .. tostring(n))

            -- zero-length constructed types
            local _, seq = asn1.decode(ldap_hex("30 00"))
            assert(type(seq) == "table" and #seq == 0, "empty SEQUENCE is an empty array")
            local _, set = asn1.decode(ldap_hex("31 00"))
            assert(type(set) == "table" and #set == 0, "empty SET is an empty array")

            -- content ends exactly on the last byte of the buffer
            local n2, v2, e2 = asn1.decode(ldap_hex("04 03 41 42 43"))
            assert(e2 == nil and v2 == "ABC", "value at buffer end")
            assert(n2 == 5, "next offset equals #der, got " .. tostring(n2))

            -- zero-length element as the very last byte pair of the buffer
            local n3, v3 = asn1.decode(ldap_hex("30 02 04 00"))
            assert(type(v3) == "table" and #v3 == 1 and v3[1] == "", "trailing empty child")
            assert(n3 == 4, "next offset " .. tostring(n3))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: child TLVs are bounded exactly by the parent's content
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- child ends EXACTLY on the parent boundary: must decode
            local n, v, e = asn1.decode(ldap_hex("30 05 04 03 41 42 43"))
            assert(e == nil, "exact fit must not error: " .. tostring(e))
            assert(type(v) == "table" and #v == 1 and v[1] == "ABC", "exact-fit value")
            assert(n == 7, "next offset " .. tostring(n))

            -- two children ending exactly on both parent and buffer boundary
            local n2, v2, e2 = asn1.decode(ldap_hex("30 06 04 01 41 04 01 42"))
            assert(e2 == nil and #v2 == 2 and v2[1] == "A" and v2[2] == "B", "two exact children")
            assert(n2 == 8, "next offset " .. tostring(n2))

            -- child overshoots parent by exactly 1 byte, buffer long enough: reject
            local _, v3, e3 = asn1.decode(ldap_hex("30 04 04 03 41 42 43"))
            assert(v3 == nil and e3 ~= nil, "overshoot by 1 must be rejected")

            -- child header itself is truncated by the parent bound
            local _, v4, e4 = asn1.decode(ldap_hex("30 01 04 03 41 42 43"))
            assert(v4 == nil and e4 ~= nil, "truncated child header must be rejected")

            -- one stray byte left inside the parent after the last child
            local _, v5, e5 = asn1.decode(ldap_hex("30 07 04 01 41 04 01 42 43"))
            assert(v5 == nil and e5 ~= nil, "leftover byte inside parent must be rejected")

            -- MAX_DECODE_DEPTH: 100 levels ok, 101 rejected, and neither raises
            local function nest(k)
                local s = ldap_hex("04 00")
                for _ = 1, k do
                    s = asn1.put_object(asn1.TAG.SEQUENCE, asn1.CLASS.UNIVERSAL, 1, s)
                end
                return s
            end
            local ok100, _, _, e100 = pcall(asn1.decode, nest(100))
            assert(ok100, "depth 100 must not raise")
            assert(e100 == nil, "depth 100 must decode, got " .. tostring(e100))
            local ok101, _, v101, e101 = pcall(asn1.decode, nest(101))
            assert(ok101, "depth 101 must not raise")
            assert(v101 == nil and e101 ~= nil, "depth 101 must be rejected")
            local okdeep, _, vdeep, edeep = pcall(asn1.decode, nest(2000))
            assert(okdeep, "depth 2000 must not raise (no C-stack blowout)")
            assert(vdeep == nil and edeep ~= nil, "depth 2000 must be rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: zero-length children always advance pos (no spin in decode_children)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- zero-length child still costs a 2-byte header, so pos always advances
            local n, v, e = asn1.decode(ldap_hex("30 06 04 00 04 00 04 00"))
            assert(e == nil, "three empty children must decode: " .. tostring(e))
            assert(type(v) == "table" and #v == 3, "three empty children, got " ..
                   tostring(type(v) == "table" and #v or v))
            assert(v[1] == "" and v[2] == "" and v[3] == "", "all empty")
            assert(n == 8, "next offset " .. tostring(n))

            -- stress: 1000 zero-length children must terminate, not spin
            local body = string.rep(ldap_hex("04 00"), 1000)
            local seq = asn1.put_object(asn1.TAG.SEQUENCE, asn1.CLASS.UNIVERSAL, 1, body)
            local n2, v2, e2 = asn1.decode(seq)
            assert(e2 == nil, "1000 empty children: " .. tostring(e2))
            assert(#v2 == 1000, "1000 children, got " .. tostring(#v2))
            assert(n2 == #seq, "consumed whole buffer")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: bytes trailing a SearchResultEntry member are rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- parse_search_entry stops at attrs end, not op end: trailing bytes ride along
            local baseline = assert(protocol.decode_message(
                ldap_hex("30 0a 02 01 03 64 05 04 01 78 30 00")))
            assert(baseline.entry_dn == "x", "baseline decodes")

            -- same entry, op grown from 5 to 9 bytes with `de ad be ef` appended
            local res, err = protocol.decode_message(
                ldap_hex("30 0e 02 01 03 64 09 04 01 78 30 00 de ad be ef"))
            assert(res == nil, "trailing bytes inside the op must not decode " ..
                   "(got entry_dn=" .. tostring(res and res.entry_dn) .. ")")
            assert(err ~= nil, "trailing bytes inside the op must report an error")

            -- a trailing element that is itself well-formed BER is equally invalid
            local res2, err2 = protocol.decode_message(
                ldap_hex("30 0f 02 01 03 64 0a 04 01 78 30 00 04 03 41 42 43"))
            assert(res2 == nil and err2 ~= nil, "trailing TLV inside the op must be rejected")

            -- one level deeper: PartialAttribute ::= SEQUENCE { type, vals } has
            -- exactly two components, so bytes after vals are equally invalid
            local inner = assert(protocol.decode_message(ldap_hex(
                "30 15 02 01 03 64 10 04 01 78 30 0b 30 09 04 02 63 6e 31 03 04 01 41")))
            assert(inner.attributes.cn[1] == "A", "inner baseline decodes")

            -- same attribute, PartialAttribute grown by `de ad` after vals
            local res3, err3 = protocol.decode_message(ldap_hex(
                "30 17 02 01 03 64 12 04 01 78 30 0d 30 0b 04 02 63 6e 31 03 04 01 41 de ad"))
            assert(res3 == nil, "trailing bytes in PartialAttribute must not decode " ..
                   "(got cn=" .. tostring(res3 and res3.attributes.cn[1]) .. ")")
            assert(err3 ~= nil, "trailing bytes in PartialAttribute must report an error")

            -- and a well-formed TLV hidden in that same gap
            local res4, err4 = protocol.decode_message(ldap_hex(
                "30 1a 02 01 03 64 15 04 01 78 30 10 30 0e 04 02 63 6e 31 03 " ..
                "04 01 41 04 03 41 42 43"))
            assert(res4 == nil and err4 ~= nil,
                   "trailing TLV in PartialAttribute must be rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 8: BER leniency on non-minimal lengths is preserved (guard rail)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- RFC 4511 s5.1 wants DER, but real servers emit BER non-minimal lengths: keep them
            local _, v, e = asn1.decode(ldap_hex("04 81 03 41 42 43"))
            assert(e == nil and v == "ABC", "1-octet long form must still decode, got " ..
                   tostring(v) .. "/" .. tostring(e))
            local _, v2, e2 = asn1.decode(ldap_hex("04 82 00 03 41 42 43"))
            assert(e2 == nil and v2 == "ABC", "2-octet long form must still decode")

            -- hl reflects the non-minimal header, and the next offset accounts for it
            local o = assert(asn1.get_object(ldap_hex("04 81 03 41 42 43")))
            assert(o.hl == 3 and o.len == 3 and o.offset == 3, "hl/len/offset " ..
                   o.hl .. "/" .. o.len .. "/" .. o.offset)
            local n = asn1.decode(ldap_hex("04 81 03 41 42 43"))
            assert(n == 6, "next offset must be 6, got " .. tostring(n))

            -- nested inside a parent whose length accounts for the longer header
            local _, arr, e3 = asn1.decode(ldap_hex("30 06 04 81 03 41 42 43"))
            assert(e3 == nil, "non-minimal child: " .. tostring(e3))
            assert(type(arr) == "table" and #arr == 1 and arr[1] == "ABC", "non-minimal child value")

            -- end to end: BindResponse matchedDN carries a 1-octet long-form length
            local res = assert(protocol.decode_message(
                ldap_hex("30 0e 02 01 01 61 09 0a 01 00 04 81 01 41 04 00")))
            assert(res.result_code == 0, "code")
            assert(res.matched_dn == "A", "matched_dn " .. tostring(res.matched_dn))
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
