# Test vectors: rasn v0.6.1 https://github.com/librasn/rasn/blob/v0.6.1/src/ber/de.rs

use Test::Nginx::Socket::Lua;

log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;/usr/share/lua/5.1/?.lua;;';
    lua_package_cpath 'deps/lib/lua/5.1/?.so;;';
    resolver 127.0.0.53;
_EOC_

run_tests();

__DATA__

=== TEST 1: encode() reports an explicit error for values it cannot encode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            local function must_fail(what, val, tag)
                local ok, v, err = pcall(asn1.encode, val, tag)
                if not ok then return end            -- raised: loud enough
                assert(v == nil, what .. ": encoded a value it should have rejected")
                assert(err ~= nil, what .. ": returned a silent nil with no error")
            end

            -- no tag, and the Lua type maps to no tag (asn1.lua:167-169)
            must_fail("nil value", nil, nil)
            must_fail("table value", {}, nil)
            must_fail("function value", print, nil)

            -- explicit tag that has no encoder entry
            must_fail("TAG.NULL", "x", asn1.TAG.NULL)
            must_fail("TAG.EOC", "x", asn1.TAG.EOC)
            must_fail("unknown tag 99", "x", 99)

            -- the supported paths still encode
            assert(asn1.encode("abc") == "\4\3abc", "octet string")
            assert(asn1.encode(5) == "\2\1\5", "integer")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: encode(INTEGER) must not silently truncate or saturate
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

            -- ASN1_INTEGER_set takes a C long and LuaJIT would truncate/saturate, emitting a
            -- DIFFERENT integer -- integer_encodable rejects non-integral values and |v| > 2^53
            -- in Lua before the FFI call, so the C-long hazard is prevented upstream. The
            -- encoder must return (nil, err) for these -- never raise, never substitute.
            local function must_fail(what, val)
                local v, err = asn1.encode(val, asn1.TAG.INTEGER)
                -- hex(v) must tolerate nil v: assert message is built eagerly
                assert(v == nil, what .. ": encoded as " .. hex(v or "") .. " instead of erroring")
                assert(err ~= nil, what .. ": silent nil")
            end

            must_fail("3.7 (fraction truncated to 3)", 3.7)
            must_fail("-3.7 (fraction truncated to -3)", -3.7)
            must_fail("0.5 (fraction truncated to 0)", 0.5)
            must_fail("2^63 (out of range)", 2^63)
            must_fail("1e100 (clamped to LONG_MAX)", 1e100)
            must_fail("1e300 (clamped to LONG_MAX)", 1e300)
            must_fail("-1e300 (negative out-of-range)", -1e300)
            must_fail("math.huge (clamped to LONG_MAX)", math.huge)
            must_fail("NaN (becomes 0)", 0/0)
            must_fail("2^53+2 (just past the exactness boundary)", 2^53 + 2)

            -- values that genuinely fit a long must keep working
            for _, n in ipairs({0, 1, -1, 127, -128, 128, 65536, 2147483647, 2^31, -2^31, 2^53}) do
                local enc = assert(asn1.encode(n, asn1.TAG.INTEGER), "encode " .. n)
                local _, v, err = asn1.decode(enc)
                assert(err == nil, "decode " .. n .. ": " .. tostring(err))
                assert(v == n, "round trip " .. n .. " -> " .. tostring(v))
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

=== TEST 3: encode -> decode round trip across the length-form boundaries
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            local lens = {0, 1, 2, 126, 127, 128, 129, 254, 255, 256, 257, 1000, 65535, 65536}

            for _, n in ipairs(lens) do
                local s = string.rep("A", n)
                local enc = assert(asn1.encode(s, asn1.TAG.OCTET_STRING), "OS encode n=" .. n)
                local off, v, err = asn1.decode(enc)
                assert(err == nil, "OS n=" .. n .. " err " .. tostring(err))
                assert(v == s, "OS n=" .. n .. " value mismatch (got " ..
                       (v and #v or -1) .. " bytes)")
                assert(off == #enc, "OS n=" .. n .. " consumed " .. tostring(off) ..
                       " of " .. #enc)
            end

            -- binary-safe: NUL, high bytes, and a byte that looks like a tag
            for _, s in ipairs({"", "\0", "A\0B", "\255\254\0\1", "\4\3abc", string.rep("\0", 300)}) do
                local enc = assert(asn1.encode(s, asn1.TAG.OCTET_STRING))
                local _, v = asn1.decode(enc)
                assert(v == s, "binary round trip failed for " .. #s .. " bytes")
            end

            -- constructed containers built with put_object round trip too
            for _, kids in ipairs({0, 1, 42, 43, 85, 86, 200}) do
                local body = string.rep("\4\1X", kids)   -- 3 bytes each
                for _, tag in ipairs({asn1.TAG.SEQUENCE, asn1.TAG.SET}) do
                    local enc = assert(asn1.encode(body, tag), "container encode")
                    local off, v, err = asn1.decode(enc)
                    assert(err == nil, "container err " .. tostring(err))
                    assert(type(v) == "table", "container is not a table")
                    assert(#v == kids, "container kids " .. #v .. " ~= " .. kids)
                    assert(off == #enc, "container consumed " .. tostring(off) .. "/" .. #enc)
                end
            end

            -- ENUMERATED round trip (result codes, search scope/deref)
            for _, n in ipairs({0, 1, 2, 3, 10, 32, 49, 127, 128, 255}) do
                local enc = assert(asn1.encode(n, asn1.TAG.ENUMERATED))
                local _, v, err = asn1.decode(enc)
                assert(err == nil and v == n, "ENUM " .. n .. " -> " .. tostring(v))
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

=== TEST 4: BOOLEAN encodes boolean-ness, not Lua truthiness, and survives a round trip
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local protocol = require("resty.ldap.protocol")
            local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

            local function must_not_be_true(what, val)
                local ok, v = pcall(asn1.encode, val, asn1.TAG.BOOLEAN)
                if not ok then return end                 -- rejecting is fine
                if v == nil then return end               -- so is nil
                assert(v ~= "\1\1\255", what .. " encoded as BOOLEAN TRUE (" .. hex(v) .. ")")
            end
            must_not_be_true("the number 0", 0)
            must_not_be_true("the empty string", "")
            must_not_be_true("the string 'false'", "false")

            assert(asn1.encode(true, asn1.TAG.BOOLEAN) == "\1\1\255", "true -> ff")
            assert(asn1.encode(false, asn1.TAG.BOOLEAN) == "\1\1\0", "false -> 00")

            -- Round trip: a BOOLEAN the library encoded must not decode to a silent nil
            for _, b in ipairs({true, false}) do
                local enc = assert(asn1.encode(b, asn1.TAG.BOOLEAN))
                local off, v, err = asn1.decode(enc)
                assert(off == #enc or err ~= nil, "boolean offset")
                assert(v == b or err ~= nil,
                       "encode(" .. tostring(b) .. ") decoded to a silent nil")
            end

            -- protocol consequence: types_only=0 must not encode typesOnly=TRUE
            local req = assert(protocol.search_request("dc=x", 2, 0, 0, 0, 0, "(cn=a)", {}))
            assert(not req:find("\1\1\255", 1, true),
                   "search_request(types_only=0) encoded typesOnly=TRUE: " .. hex(req))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: put_object never emits a header whose length disagrees with its payload
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

            local function check(what, ...)
                local ok, out, err = pcall(asn1.put_object, ...)
                if not ok then return end                       -- raised: acceptable
                if out == nil then
                    assert(err ~= nil, what .. ": silent nil from put_object")
                    return
                end
                local obj = asn1.get_object(out)
                assert(obj, what .. ": emitted unparseable bytes " .. hex(out))
                assert(obj.hl + obj.len == #out,
                       what .. ": header declares " .. obj.len .. " content bytes but " ..
                       (#out - obj.hl) .. " follow (" .. hex(out) .. ")")
            end

            check("number payload", 0, asn1.CLASS.CONTEXT_SPECIFIC, 0, 12345)
            check("boolean payload", 0, asn1.CLASS.CONTEXT_SPECIFIC, 0, true)
            check("table payload", 0, asn1.CLASS.CONTEXT_SPECIFIC, 0, {})

            -- negative length is already rejected, and must stay rejected
            local out, err = asn1.put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, nil, -1)
            assert(out == nil and err ~= nil, "negative length rejected")

            -- string and header-only payloads stay correct
            for _, n in ipairs({0, 1, 127, 128, 255, 256, 65535, 65536}) do
                local enc = assert(asn1.put_object(asn1.TAG.SEQUENCE, asn1.CLASS.UNIVERSAL, 1,
                                                   string.rep("A", n)))
                local obj = assert(asn1.get_object(enc), "n=" .. n)
                assert(obj.len == n and obj.hl + n == #enc, "n=" .. n .. " header")
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

=== TEST 6: simple_bind_request must not silently mis-encode a non-string dn/password
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local protocol = require("resty.ldap.protocol")
            local function hex(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

            local function bind_fields(msg)
                local env = assert(asn1.get_object(msg, 0), "envelope")
                local op = assert(asn1.get_object(msg, env.offset + 3), "protocolOp")
                assert(op.class == asn1.CLASS.APPLICATION and op.tag == 0, "not a BindRequest")
                local stop = op.offset + op.len
                local ver = assert(asn1.get_object(msg, op.offset, stop), "version")
                local name = assert(asn1.get_object(msg, ver.offset + ver.len, stop), "name")
                local auth = assert(asn1.get_object(msg, name.offset + name.len, stop), "auth")
                return name, auth, stop
            end

            -- baseline
            local ok_msg = assert(protocol.simple_bind_request("cn=admin,dc=x", "s3cret"))
            local name, auth, stop = bind_fields(ok_msg)
            assert(name.tag == asn1.TAG.OCTET_STRING and name.class == asn1.CLASS.UNIVERSAL, "name tag")
            assert(auth.offset + auth.len == stop, "auth covers the rest of the BindRequest")

            -- numeric password: put_object emits a zero-length (unauthenticated) bind + stray bytes
            local numeric_pw = assert(protocol.simple_bind_request("cn=admin,dc=x", 12345))
            local _, a2, stop2 = bind_fields(numeric_pw)
            assert(a2.len > 0,
                   "numeric password produced a ZERO-LENGTH (unauthenticated) simple bind: " ..
                   hex(numeric_pw))
            assert(a2.offset + a2.len == stop2,
                   "numeric password left " .. (stop2 - a2.offset - a2.len) ..
                   " stray bytes after the auth element: " .. hex(numeric_pw))

            -- numeric dn: encode() dispatches on Lua type, emitting INTEGER not OCTET STRING
            local ok3, numeric_dn = pcall(protocol.simple_bind_request, 12345, "s3cret")
            if ok3 and numeric_dn then
                local n3 = bind_fields(numeric_dn)
                assert(n3.tag == asn1.TAG.OCTET_STRING,
                       "numeric dn encoded with tag " .. n3.tag ..
                       " (expected 4/OCTET STRING): " .. hex(numeric_dn))
            end

            -- a wrong-shape dn must be reported, not raise a bare Lua error
            local ok4, res, err4 = pcall(protocol.simple_bind_request, {}, "s3cret")
            assert(ok4, "table dn raised a raw Lua error: " .. tostring(res))
            assert(res == nil and err4 ~= nil, "table dn should return nil, err")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
