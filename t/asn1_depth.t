# Test vectors: pyasn1 v0.6.4 https://github.com/pyasn1/pyasn1/blob/v0.6.4/tests/codec/ber/test_decoder.py

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

=== TEST 1: unbounded nesting is refused with an error, never a crash
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            -- hand-rolled BER writer, independent of the library's encoder
            local function tlv(tagbyte, content)
                local n = #content
                local len
                if n < 128 then
                    len = string.char(n)
                elseif n < 256 then
                    len = string.char(0x81, n)
                elseif n < 65536 then
                    len = string.char(0x82, math.floor(n / 256), n % 256)
                else
                    len = string.char(0x83, math.floor(n / 65536),
                                      math.floor(n / 256) % 256, n % 256)
                end
                return string.char(tagbyte) .. len .. content
            end
            local function nest(tagbyte, n, inner)
                local s = inner or ""
                for _ = 1, n do s = tlv(tagbyte, s) end
                return s
            end

            for _, tb in ipairs({0x30, 0x31}) do
                local label = string.format("tag 0x%02x", tb)

                -- comfortably inside the budget: must decode
                local _, v, err = asn1.decode(nest(tb, 100))
                assert(err == nil, label .. " nest 100 errored: " .. tostring(err))
                assert(type(v) == "table", label .. " nest 100 value type")

                -- far outside it: must be a clean error, not a stack overflow
                for _, deep in ipairs({102, 500, 2000}) do
                    local off, dv, derr = asn1.decode(nest(tb, deep))
                    assert(dv == nil, label .. " nest " .. deep .. " returned a value")
                    assert(off == nil, label .. " nest " .. deep .. " returned an offset")
                    assert(derr == "max decode depth exceeded",
                           label .. " nest " .. deep .. " err = " .. tostring(derr))
                end
            end

            -- context-specific [16] is not a SEQUENCE: refused on class grounds
            local _, bv, berr = asn1.decode(nest(0xb0, 100))
            assert(bv == nil, "context [16] must not be walked as a container")
            assert(berr ~= nil, "context [16] must report an error")

            -- alternating SEQ/SET must count the same as either alone
            local mixed = ""
            for i = 1, 500 do mixed = tlv(i % 2 == 0 and 0x30 or 0x31, mixed) end
            local _, mv, merr = asn1.decode(mixed)
            assert(mv == nil and merr == "max decode depth exceeded",
                   "alternating SEQ/SET nesting err = " .. tostring(merr))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: the enforced nesting bound matches MAX_DECODE_DEPTH
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function tlv(tagbyte, content)
                local n = #content
                local len
                if n < 128 then len = string.char(n)
                elseif n < 256 then len = string.char(0x81, n)
                else len = string.char(0x82, math.floor(n / 256), n % 256) end
                return string.char(tagbyte) .. len .. content
            end
            local function nest(tagbyte, n, inner)
                local s = inner or ""
                for _ = 1, n do s = tlv(tagbyte, s) end
                return s
            end

            for _, tb in ipairs({0x30, 0x31}) do
                local label = string.format("tag 0x%02x", tb)

                local _, ok_v, ok_err = asn1.decode(nest(tb, 101))
                assert(ok_err == nil, label .. " 101 levels must decode: " .. tostring(ok_err))
                assert(type(ok_v) == "table", label .. " 101 levels value")

                local off, v, err = asn1.decode(nest(tb, 102))
                assert(v == nil, label .. " 102 levels must not yield a value")
                assert(off == nil, label .. " 102 levels must not yield an offset")
                assert(err == "max decode depth exceeded",
                       label .. " 102 levels err = " .. tostring(err))
            end

            -- same bound from a leaf: 101 containers + OCTET STRING = 102 levels, refused
            local _, okv, okerr = asn1.decode(nest(0x30, 100, string.char(0x04, 0x01, 0x41)))
            assert(okerr == nil and type(okv) == "table",
                   "100 containers + leaf must decode: " .. tostring(okerr))
            local _, lv, lerr = asn1.decode(nest(0x30, 101, string.char(0x04, 0x01, 0x41)))
            assert(lv == nil and lerr == "max decode depth exceeded",
                   "101 containers + leaf err = " .. tostring(lerr))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: the depth budget is per path, not cumulative across siblings
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function tlv(tagbyte, content)
                local n = #content
                local len
                if n < 128 then len = string.char(n)
                elseif n < 256 then len = string.char(0x81, n)
                elseif n < 65536 then len = string.char(0x82, math.floor(n / 256), n % 256)
                else len = string.char(0x83, math.floor(n / 65536),
                                       math.floor(n / 256) % 256, n % 256) end
                return string.char(tagbyte) .. len .. content
            end
            local function nest(tagbyte, n, inner)
                local s = inner or ""
                for _ = 1, n do s = tlv(tagbyte, s) end
                return s
            end

            local siblings = ""
            for _ = 1, 50 do siblings = siblings .. nest(0x30, 99) end
            local _, v, err = asn1.decode(tlv(0x30, siblings))
            assert(err == nil, "wide-and-deep-but-legal errored: " .. tostring(err))
            assert(type(v) == "table", "wide-and-deep value type")
            assert(#v == 50, "branch count " .. #v)
            assert(type(v[1]) == "table" and type(v[50]) == "table", "branches are tables")

            -- a single over-budget branch is still caught next to good siblings
            local mixed = nest(0x30, 10) .. nest(0x30, 200) .. nest(0x30, 10)
            local _, bv, berr = asn1.decode(tlv(0x30, mixed))
            assert(bv == nil, "over-budget branch must not yield a value")
            assert(berr == "max decode depth exceeded", "err = " .. tostring(berr))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: structural empties decode as empty arrays and keep their positions
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local off, v, err = asn1.decode(ldap_hex("30 00"))
            assert(err == nil, "empty SEQUENCE errored: " .. tostring(err))
            assert(type(v) == "table" and #v == 0, "empty SEQUENCE is an empty array")
            assert(off == 2, "empty SEQUENCE next offset " .. tostring(off))

            -- 31 00 : empty SET
            local off2, v2, err2 = asn1.decode(ldap_hex("31 00"))
            assert(err2 == nil, "empty SET errored: " .. tostring(err2))
            assert(type(v2) == "table" and #v2 == 0, "empty SET is an empty array")
            assert(off2 == 2, "empty SET next offset " .. tostring(off2))

            -- nesting of empties: SEQUENCE { SEQUENCE {} }
            local _, v3 = asn1.decode(ldap_hex("30 02 30 00"))
            assert(#v3 == 1, "SEQ{empty SEQ} count " .. #v3)
            assert(type(v3[1]) == "table" and #v3[1] == 0, "inner empty preserved")

            -- empty members must occupy array slots: SEQ { SEQ{}, SET{}, SEQ{SET{}} }
            local _, v4 = asn1.decode(ldap_hex("30 08 30 00 31 00 30 02 31 00"))
            assert(#v4 == 3, "mixed empties count " .. #v4)
            assert(type(v4[1]) == "table" and #v4[1] == 0, "slot 1")
            assert(type(v4[2]) == "table" and #v4[2] == 0, "slot 2")
            assert(type(v4[3]) == "table" and #v4[3] == 1, "slot 3 holds one child")
            assert(type(v4[3][1]) == "table" and #v4[3][1] == 0, "slot 3 inner empty")

            -- an empty container remains addressable at the deepest legal level
            local deep = ldap_hex("30 00")
            for _ = 1, 99 do
                local n = #deep
                local len
                if n < 128 then len = string.char(n)
                elseif n < 256 then len = string.char(0x81, n)
                else len = string.char(0x82, math.floor(n / 256), n % 256) end
                deep = string.char(0x30) .. len .. deep
            end
            local _, dv, derr = asn1.decode(deep)
            assert(derr == nil, "100 levels ending in an empty SEQ errored: " .. tostring(derr))
            local t, levels = dv, 0
            while type(t) == "table" and t[1] ~= nil do levels = levels + 1; t = t[1] end
            assert(levels == 99, "walked levels " .. levels)
            assert(type(t) == "table" and #t == 0, "innermost is the empty SEQUENCE")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: a wide, shallow document decodes completely and in linear time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            local n = 100000
            local body = string.rep("\4\1X", n)
            local der = string.char(0x30, 0x83,
                                    math.floor(#body / 65536),
                                    math.floor(#body / 256) % 256,
                                    #body % 256) .. body

            local t0 = ngx.now()
            local off, v, err = asn1.decode(der)
            ngx.update_time()
            local elapsed = ngx.now() - t0

            assert(err == nil, "wide document errored: " .. tostring(err))
            assert(type(v) == "table", "wide document value type")
            assert(#v == n, "member count " .. #v .. ", expected " .. n)
            assert(v[1] == "X" and v[n] == "X", "first/last member")
            assert(off == #der, "consumed " .. tostring(off) .. " of " .. #der)
            assert(elapsed < 2, "took " .. elapsed .. "s -- decode_children is not linear")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
