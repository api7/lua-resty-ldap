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

=== TEST 1: i2d_* output buffers must be freed, not leaked once per encode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            -- i2d with *pp==NULL makes OpenSSL malloc a buffer encode leaks; GC can't reclaim it
            local function rss()
                local f = assert(io.open("/proc/self/statm"))
                local s = f:read("*l")
                f:close()
                return tonumber(s:match("^%d+%s+(%d+)")) * 4096
            end

            local N, SZ = 20000, 4000
            local payload = string.rep("A", SZ)

            -- Control: the SEQUENCE encoder (asn1_put_object) allocates nothing
            collectgarbage("collect")
            local b1 = rss()
            for _ = 1, N do
                local s = asn1.encode(payload, asn1.TAG.SEQUENCE)
                assert(#s == SZ + 4, "control encoding size")
            end
            collectgarbage("collect")
            local control = rss() - b1

            -- Subject: the OCTET STRING encoder goes through i2d.
            collectgarbage("collect")
            local b2 = rss()
            for _ = 1, N do
                local s = asn1.encode(payload, asn1.TAG.OCTET_STRING)
                assert(#s == SZ + 4, "subject encoding size")
            end
            collectgarbage("collect")
            local subject = rss() - b2

            local excess = subject - control
            -- correct frees each i2d buffer, so both paths cost the same; leaking = ~80MB excess
            assert(excess < 8 * 1024 * 1024,
                   string.format("i2d output buffers leaked: %.1f MB excess over the "
                                 .. "put_object control across %d encodes (control %.1f MB, "
                                 .. "subject %.1f MB)",
                                 excess / 1048576, N, control / 1048576, subject / 1048576))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: start offset must be validated as a non-negative integer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- get_object never checks start >= 0, so a negative start reads out of bounds
            local der = ldap_hex("04 03 41 42 43")

            for _, start in ipairs({-1, -2, -4, -16}) do
                local o, err = asn1.get_object(der, start, #der)
                assert(o == nil, "get_object must reject negative start " .. start
                                 .. " (returned a fabricated object instead of reading out of bounds)")
                assert(err ~= nil, "negative start " .. start .. " must report an error")

                local off, v, derr = asn1.decode(der, start)
                assert(off == nil and derr ~= nil,
                       "decode must reject negative offset " .. start)
            end

            -- a negative start can yield a negative obj.offset, slicing from the buffer tail
            local o2 = asn1.get_object(der, -4)
            assert(o2 == nil, "negative start must never produce an object with a negative offset")

            -- fractional offsets make hl fractional, then marshalled into d2i's long length
            local der2 = ldap_hex("41 04 03 41 42 43 00 00 00 00")
            local o3, err3 = asn1.get_object(der2, 1.9, #der2)
            assert(o3 == nil, "get_object must reject a fractional start"
                              .. (o3 and (" (got hl=" .. tostring(o3.hl) .. ")") or ""))
            assert(err3 ~= nil, "fractional start must report an error")

            local _, v3, derr3 = asn1.decode(der2, 1.2)
            assert(v3 == nil and derr3 ~= nil,
                   "decode must reject a fractional offset instead of silently flooring it")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: put_object header length must agree with the bytes it returns
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            -- Invariant: put_object returns exactly one TLV; reparsing consumes it all
            local function self_consistent(res, what)
                assert(type(res) == "string", what .. ": expected a string")
                local o = assert(asn1.get_object(res), what .. ": result does not parse")
                assert(o.hl + o.len == #res,
                       string.format("%s: header declares %d content bytes after a %d-byte "
                                     .. "header but %d bytes were returned",
                                     what, o.len, o.hl, #res))
            end

            -- Sanity: string payloads hold the invariant today.
            for _, n in ipairs({0, 1, 127, 128, 300}) do
                self_consistent(asn1.put_object(asn1.TAG.OCTET_STRING, asn1.CLASS.UNIVERSAL,
                                                0, string.rep("A", n)),
                                "string payload n=" .. n)
            end

            -- a non-string payload is treated as length 0 but still appended: header disagrees
            local res, err = asn1.put_object(asn1.TAG.OCTET_STRING, asn1.CLASS.UNIVERSAL, 0, 12345)
            if res ~= nil then
                self_consistent(res, "number payload 12345")
            else
                assert(err ~= nil, "rejecting a non-string payload must report an error")
            end

            -- length above INT_MAX is silently clamped by FFI; the len < 0 guard misses it
            for _, n in ipairs({2147483648, 4294967296, 2 ^ 53}) do
                local r2, e2 = asn1.put_object(asn1.TAG.OCTET_STRING, asn1.CLASS.UNIVERSAL, 0, nil, n)
                assert(r2 == nil, "length " .. string.format("%.0f", n)
                                  .. " exceeds the int the C API accepts and must be rejected, "
                                  .. "not silently clamped")
                assert(e2 ~= nil, "over-large length must report an error")
            end

            -- Non-integer lengths land in the same `int length` parameter.
            local r3 = asn1.put_object(asn1.TAG.OCTET_STRING, asn1.CLASS.UNIVERSAL, 0, nil, 3.7)
            assert(r3 == nil, "a fractional length must be rejected, not truncated to 3")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: encode(INTEGER) must not silently substitute a different value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            -- ASN1_INTEGER_set takes a C long; LuaJIT truncates/saturates, emitting a different int
            local function roundtrip(v)
                local enc = asn1.encode(v, asn1.TAG.INTEGER)
                if enc == nil then return nil end
                return (select(2, asn1.decode(enc)))
            end

            -- Values a C long represents exactly must round-trip.
            for _, v in ipairs({0, 1, -1, 127, 128, -128, 2147483647, 2147483648, 2 ^ 53}) do
                assert(roundtrip(v) == v,
                       "exact value " .. string.format("%.0f", v) .. " must round-trip")
            end

            -- Non-integers must be refused, never silently truncated.
            for _, v in ipairs({3.7, -3.7, 0.5}) do
                assert(asn1.encode(v, asn1.TAG.INTEGER) == nil,
                       "encode(" .. tostring(v) .. ", INTEGER) must be refused, not truncated to "
                       .. tostring(roundtrip(v)))
            end

            -- Values outside the C long range must be refused, never saturated.
            for _, v in ipairs({2 ^ 63, 1e300, -1e300}) do
                assert(asn1.encode(v, asn1.TAG.INTEGER) == nil,
                       "encode(" .. tostring(v) .. ", INTEGER) must be refused, not saturated to "
                       .. tostring(roundtrip(v)))
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

=== TEST 5: high-tag-form encodings of low tags must not alias the short form
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- high-tag-number form aliases low tags (1f 04 == 04); RFC 4511 defines no tag >= 31
            local canonical = select(2, asn1.decode(ldap_hex("04 03 41 42 43")))
            assert(canonical == "ABC", "canonical OCTET STRING still decodes")

            for _, alias in ipairs({"1f 04 03 41 42 43",
                                    "1f 80 04 03 41 42 43",
                                    "1f 80 80 80 04 03 41 42 43"}) do
                local o, gerr = asn1.get_object(ldap_hex(alias))
                assert(o == nil, "high-tag form '" .. alias .. "' must be rejected, not reported as tag "
                                 .. tostring(o and o.tag))
                assert(gerr ~= nil, "high-tag form '" .. alias .. "' must report an error")

                local _, v, derr = asn1.decode(ldap_hex(alias))
                assert(v == nil, "high-tag form '" .. alias .. "' must not decode to " .. tostring(v))
                assert(derr ~= nil, "high-tag form '" .. alias .. "' must report a decode error")
            end

            -- the alias reaches the LDAP message layer (envelope 30 -> 3f 80 10, op 61 -> 7f 01)
            local ok_res = assert(protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(ok_res.result_code == 0, "canonical BindResponse still parses")

            local bad1, e1 = protocol.decode_message(ldap_hex("3f 80 10 0c 02 01 01 61 07 0a 01 00 04 00 04 00"))
            assert(bad1 == nil and e1 ~= nil,
                   "an LDAPMessage envelope in high-tag form must be rejected")

            local bad2, e2 = protocol.decode_message(ldap_hex("30 0d 02 01 01 7f 01 07 0a 01 00 04 00 04 00"))
            assert(bad2 == nil and e2 ~= nil,
                   "a protocolOp tag in high-tag form must be rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: FFI marshalling invariants that currently hold (regression guard)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- (a) get_object return contract: reachable values 0x00/0x20/0x21/0x80|x; 0x01 test load-bearing
            local o0 = assert(asn1.get_object(ldap_hex("04 03 41 42 43")))
            assert(o0.cons == false, "ret 0x00 -> primitive")
            local o20 = assert(asn1.get_object(ldap_hex("30 03 02 01 05")))
            assert(o20.cons == true, "ret 0x20 -> constructed")
            -- ret 0x21: constructed indefinite length, forbidden by RFC 4511 s5.1
            assert(asn1.get_object(ldap_hex("30 80 02 01 05 00 00")) == nil,
                   "ret 0x21 (indefinite length) must be rejected by the 0x01 bit")
            -- ret 0x80: TOO_LONG. OpenSSL still writes the shared buffers; don't trust them
            assert(asn1.get_object(ldap_hex("30 05 02 01")) == nil, "ret 0x80 must be rejected")
            assert(asn1.get_object(ldap_hex("1f")) == nil, "truncated high-tag header must be rejected")

            -- (b) shared module-level buffers must be snapshotted so nested calls don't clobber
            local leaf = ldap_hex("31 81 84") .. string.rep("\4\1X", 44)
            local der  = ldap_hex("30 81 87") .. leaf
            local outer = assert(asn1.get_object(der))
            assert(outer.tag == 16 and outer.len == 135 and outer.hl == 3 and outer.offset == 3,
                   "outer header parsed")
            local inner = assert(asn1.get_object(der, outer.offset, outer.offset + outer.len))
            local deep  = assert(asn1.get_object(der, inner.offset, inner.offset + inner.len))
            assert(inner.tag == 17 and inner.hl == 3 and inner.len == 132, "inner header parsed")
            assert(deep.tag == 4 and deep.hl == 2 and deep.len == 1, "leaf header parsed")
            assert(outer.tag == 16 and outer.len == 135 and outer.hl == 3 and outer.offset == 3
                   and outer.cons == true,
                   "nested get_object calls must not disturb an outer result")
            assert(outer ~= inner and inner ~= deep, "each call returns a distinct table")

            -- (c) offset/hl/len must be plain Lua numbers, not cdata
            assert(type(outer.len) == "number", "len is a Lua number")
            assert(type(outer.offset) == "number", "offset is a Lua number")
            assert(type(outer.hl) == "number", "hl is a Lua number")

            -- (d) hdrbuf is 16 bytes; put_object worst case is 11 (high-tag path), not 6
            local worst = asn1.put_object(2147483647, asn1.CLASS.PRIVATE, 1, nil, 2147483647)
            assert(#worst == 11,
                   "worst-case ASN1_put_object header is 11 bytes, got " .. #worst)
            assert(#worst <= 16, "worst-case header must fit hdrbuf")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
