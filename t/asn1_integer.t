# pyasn1 v0.6.4 IntegerDecoderTestCase: https://github.com/pyasn1/pyasn1/blob/v0.6.4/tests/codec/ber/test_decoder.py
# Go go1.26.3 int64TestData: https://github.com/golang/go/blob/go1.26.3/src/encoding/asn1/asn1_test.go

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

=== TEST 1: INTEGER/ENUMERATED inside the exactly-representable range decode correctly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local cases = {
                {"02 01 00", 0},
                {"02 01 01", 1},
                {"02 01 ff", -1},
                {"02 01 7f", 127},
                {"02 02 00 80", 128},
                {"02 01 80", -128},
                {"02 02 00 ff", 255},
                {"02 02 01 00", 256},
                {"02 02 ff 7f", -129},
                {"02 04 7f ff ff ff", 2147483647},          -- 2^31-1
                {"02 05 00 80 00 00 00", 2147483648},       -- 2^31
                {"02 04 80 00 00 00", -2147483648},
                {"02 05 00 ff ff ff ff", 4294967295},       -- 2^32-1
                {"02 05 01 00 00 00 00", 4294967296},       -- 2^32
                {"02 07 1f ff ff ff ff ff ff", 9007199254740991},  -- 2^53-1
                {"02 07 20 00 00 00 00 00 00", 9007199254740992},  -- 2^53
                {"02 07 e0 00 00 00 00 00 00", -9007199254740992}, -- -2^53, negative boundary
                -- ENUMERATED must agree with INTEGER over the same range
                {"0a 01 00", 0},
                {"0a 01 ff", -1},
                {"0a 01 31", 49},                           -- invalidCredentials
                {"0a 01 20", 32},                           -- noSuchObject
                {"0a 04 7f ff ff ff", 2147483647},
                {"0a 05 00 ff ff ff ff", 4294967295},
                {"0a 05 01 00 00 00 00", 4294967296},
            }
            for _, c in ipairs(cases) do
                local _, v, err = asn1.decode(ldap_hex(c[1]))
                assert(err == nil, c[1] .. " unexpected error: " .. tostring(err))
                assert(v == c[2], c[1] .. " decoded " .. tostring(v) .. ", want " .. tostring(c[2]))
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

=== TEST 2: no non-zero encoding may decode to 0 (resultCode success cannot be forged)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            for _, tag in ipairs({2, 10}) do
                for b = 0, 255 do
                    local _, v = asn1.decode(string.char(tag, 1, b))
                    if v == 0 then
                        assert(b == 0, string.format("%02x 01 %02x decoded to 0", tag, b))
                    end
                end
                for b1 = 0, 255 do
                    for b2 = 0, 255 do
                        local _, v = asn1.decode(string.char(tag, 2, b1, b2))
                        assert(v ~= 0, string.format("%02x 02 %02x %02x decoded to 0", tag, b1, b2))
                    end
                end
            end

            -- LDAPMessage layer: overflowing resultCodes may never surface as 0 (success).
            local hostile = {
                "30 14 02 01 01 61 0f 0a 09 00 ff ff ff ff ff ff ff ff 04 00 04 00",  -- 2^64-1
                "30 14 02 01 01 61 0f 0a 09 01 00 00 00 00 00 00 00 00 04 00 04 00",  -- 2^64
                "30 14 02 01 01 61 0f 0a 09 ff 7f ff ff ff ff ff ff ff 04 00 04 00",  -- -(2^63+1)
                "30 14 02 01 01 61 0f 0a 09 fe 00 00 00 00 00 00 00 00 04 00 04 00",  -- -2^65
            }
            for _, pkt in ipairs(hostile) do
                local res = protocol.decode_message(ldap_hex(pkt))
                if res then
                    assert(res.result_code ~= 0, "overflow forged a success resultCode: " .. pkt)
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

=== TEST 3: an INTEGER too large to represent exactly must error, not become -1
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local overflow = {
                {"02 09 00 80 00 00 00 00 00 00 00", "2^63"},
                {"02 09 00 80 00 00 00 00 00 00 01", "2^63+1"},
                {"02 09 00 ff ff ff ff ff ff ff ff", "2^64-1"},
                {"02 09 01 00 00 00 00 00 00 00 00", "2^64"},
                {"02 09 ff 7f ff ff ff ff ff ff ff", "-(2^63+1)"},
                {"02 09 fe 00 00 00 00 00 00 00 00", "-2^65"},
                {"02 0c 01 00 00 00 00 00 00 00 00 00 00 00", "2^88"},
                {"02 08 7f ff ff ff ff ff ff ff", "2^63-1 (maxint64, 8-octet: exact_number path, not the len>8 guard)"},
                {"02 09 80 00 00 00 00 00 00 00 00", "9-octet negative (Go encoding/asn1 int64 overflow vector)"},
            }
            for _, c in ipairs(overflow) do
                local _, v, err = asn1.decode(ldap_hex(c[1]))
                assert(err ~= nil,
                    c[2] .. " (" .. c[1] .. ") must be rejected, got " .. tostring(v))
                assert(v == nil, c[2] .. " must not yield a value alongside the error")
            end

            -- and the sentinel must stay distinguishable from a genuine -1
            local _, real = asn1.decode(ldap_hex("02 01 ff"))
            assert(real == -1, "genuine -1 must still decode as -1, got " .. tostring(real))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: an ENUMERATED too large to represent must error, and must never flip sign
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local overflow = {
                {"0a 09 00 80 00 00 00 00 00 00 00", "2^63"},
                {"0a 09 00 ff ff ff ff ff ff ff ff", "2^64-1"},
                {"0a 09 01 00 00 00 00 00 00 00 00", "2^64"},
                {"0a 09 ff 7f ff ff ff ff ff ff ff", "-(2^63+1)"},
                {"0a 09 ff 00 00 00 00 00 00 00 00", "-2^64"},
                {"0a 09 fe 00 00 00 00 00 00 00 00", "-2^65"},
                {"0a 0c 01 00 00 00 00 00 00 00 00 00 00 00", "2^88"},
                {"0a 07 20 00 00 00 00 00 01", "2^53+1 (7-octet: ENUMERATED exact_number path, not the len>8 guard)"},
            }
            for _, c in ipairs(overflow) do
                local _, v, err = asn1.decode(ldap_hex(c[1]))
                assert(err ~= nil,
                    c[2] .. " (" .. c[1] .. ") must be rejected, got " .. tostring(v))
                assert(v == nil, c[2] .. " must not yield a value alongside the error")
            end

            -- sign inversion: -2^65 is negative; decoder must never report positive.
            local _, neg = asn1.decode(ldap_hex("0a 09 fe 00 00 00 00 00 00 00 00"))
            assert(neg == nil or neg < 0,
                "-2^65 decoded as positive " .. tostring(neg))

            -- 4294967295 (< 2^53) must still decode; ENUM counterpart of TEST 3's -1 guard.
            local _, legit = asn1.decode(ldap_hex("0a 05 00 ff ff ff ff"))
            assert(legit == 4294967295, "genuine 4294967295 broke: " .. tostring(legit))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: distinct integers above 2^53 must not collapse onto the same value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local pairs_ = {
                {"02 07 20 00 00 00 00 00 00", "02 07 20 00 00 00 00 00 01", "2^53 vs 2^53+1"},
                {"02 08 7f ff ff ff ff ff ff fe", "02 08 7f ff ff ff ff ff ff ff", "2^63-2 vs 2^63-1"},
                {"0a 07 20 00 00 00 00 00 00", "0a 07 20 00 00 00 00 00 01", "ENUM 2^53 vs 2^53+1"},
                {"02 07 df ff ff ff ff ff ff", "02 07 e0 00 00 00 00 00 00", "-(2^53+1) vs -2^53"},
            }
            for _, c in ipairs(pairs_) do
                local _, a, aerr = asn1.decode(ldap_hex(c[1]))
                local _, b, berr = asn1.decode(ldap_hex(c[2]))
                assert(not (aerr == nil and berr == nil and a == b),
                    c[3] .. " both decoded to " .. tostring(a))
            end

            -- 2^53+1 is 9007199254740993; returning 9007199254740992 is silently wrong.
            local _, v, err = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 01"))
            assert(err ~= nil or v ~= 9007199254740992,
                "2^53+1 silently decoded as 2^53")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: overflowing messageID/resultCode is rejected at the LDAPMessage layer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad = {
                {"30 14 02 09 00 ff ff ff ff ff ff ff ff 61 07 0a 01 00 04 00 04 00", "messageID 2^64-1"},
                {"30 12 02 07 20 00 00 00 00 00 01 61 07 0a 01 00 04 00 04 00", "messageID 2^53+1"},
                {"30 14 02 01 01 61 0f 0a 09 00 ff ff ff ff ff ff ff ff 04 00 04 00", "resultCode 2^64-1 (must never surface as resultCode -1)"},
                {"30 14 02 01 01 61 0f 0a 09 fe 00 00 00 00 00 00 00 00 04 00 04 00", "resultCode -2^65"},
            }
            for _, c in ipairs(bad) do
                local res, err = protocol.decode_message(ldap_hex(c[1]))
                assert(res == nil and err ~= nil,
                    c[2] .. " must be rejected; got code=" ..
                    tostring(res and res.result_code) .. " msgid=" ..
                    tostring(res and res.message_id))
            end

            -- distinct wire messageIDs (2^53+1 vs 2^53) must never correlate to the same in-process id
            local r1 = protocol.decode_message(ldap_hex("30 12 02 07 20 00 00 00 00 00 01 61 07 0a 01 00 04 00 04 00"))
            local r2 = protocol.decode_message(ldap_hex("30 12 02 07 20 00 00 00 00 00 00 61 07 0a 01 00 04 00 04 00"))
            assert(not (r1 and r2 and r1.message_id == r2.message_id),
                "distinct wire messageIDs collided on " .. tostring(r1 and r1.message_id))

            -- a well-formed message still decodes
            local ok_res = assert(protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(ok_res.result_code == 0 and ok_res.message_id == 1, "baseline intact")

            -- RFC 4511 maxInt messageID still decodes (Go go1.26.3 encoding/asn1 INTEGER-boundary vector)
            local max_res = assert(protocol.decode_message(ldap_hex("30 0f 02 04 7f ff ff ff 61 07 0a 01 00 04 00 04 00")))
            assert(max_res.message_id == 2147483647, "maxInt messageID " .. tostring(max_res.message_id))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: messageID outside 0..maxInt is rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- representable, so TEST 6's overflow guard never saw these
            local bad = {
                {"30 0c 02 01 ff 65 07 0a 01 00 04 00 04 00", "messageID -1"},
                {"30 10 02 05 00 80 00 00 00 65 07 0a 01 00 04 00 04 00", "messageID maxInt+1"},
                {"30 10 02 05 ff 7f ff ff ff 65 07 0a 01 00 04 00 04 00", "messageID -maxInt-2"},
            }
            for _, c in ipairs(bad) do
                local res, err = protocol.decode_message(ldap_hex(c[1]))
                assert(res == nil and err ~= nil,
                    c[2] .. " must be rejected; got " .. tostring(res and res.message_id))
            end

            -- both ends of the legal range still decode
            local zero = assert(protocol.decode_message(ldap_hex(
                "30 0c 02 01 00 65 07 0a 01 00 04 00 04 00")))
            assert(zero.message_id == 0, "messageID 0")
            local max = assert(protocol.decode_message(ldap_hex(
                "30 0f 02 04 7f ff ff ff 65 07 0a 01 00 04 00 04 00")))
            assert(max.message_id == 2147483647, "messageID maxInt")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
