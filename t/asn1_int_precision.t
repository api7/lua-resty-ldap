# Go go1.26.3 encoding/asn1 int64TestData: https://github.com/golang/go/blob/go1.26.3/src/encoding/asn1/asn1_test.go

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

=== TEST 1: INTEGER above 2^53 must not silently collapse onto its neighbour
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, v, err = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 01"))
            assert(v == nil, "2^53+1 must not yield a value, got " .. tostring(v))
            assert(err ~= nil, "2^53+1 must report an error")

            -- Different encodings must never decode to the same Lua value.
            local _, a = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 01"))  -- 2^53+1
            local _, b = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 00"))  -- 2^53
            assert(not (a ~= nil and a == b),
                   "2^53+1 and 2^53 decoded to the same value " .. tostring(a))

            -- Negative side is symmetric: -(2^53+1) vs -2^53.
            local _, c = asn1.decode(ldap_hex("02 07 df ff ff ff ff ff ff"))  -- -(2^53+1)
            local _, d = asn1.decode(ldap_hex("02 07 e0 00 00 00 00 00 00"))  -- -2^53
            assert(not (c ~= nil and c == d),
                   "-(2^53+1) and -2^53 decoded to the same value " .. tostring(c))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 2: 64-bit-range INTEGER is rejected rather than returned off-by-one
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local _, v, err = asn1.decode(ldap_hex("02 08 7f ff ff ff ff ff ff ff"))
            assert(v == nil, "maxint64 must not yield a value, got " .. tostring(v))
            assert(err ~= nil, "maxint64 must report an error")

            -- ENUMERATED shares the marshalling (LDAP resultCode); reject identically.
            local _, e, eerr = asn1.decode(ldap_hex("0a 07 20 00 00 00 00 00 01"))
            assert(e == nil, "oversized ENUMERATED must not yield a value, got " .. tostring(e))
            assert(eerr ~= nil, "oversized ENUMERATED must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 3: exactly-representable integers still decode (fix must not over-reject)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            local cases = {
                { "02 01 00",             0 },
                { "02 01 05",             5 },
                { "02 01 ff",            -1 },
                { "02 04 7f ff ff ff",    2147483647 },   -- max messageID, RFC 4511
                { "02 04 80 00 00 00",   -2147483648 },
                { "0a 01 31",             49 },           -- ENUMERATED resultCode
            }
            for _, c in ipairs(cases) do
                local _, v, err = asn1.decode(ldap_hex(c[1]))
                assert(err == nil, c[1] .. " unexpected error: " .. tostring(err))
                assert(v == c[2], c[1] .. " got " .. tostring(v) .. " want " .. tostring(c[2]))
            end

            -- 2^53 and -2^53 are the boundary and exactly representable; must be accepted.
            local _, hi, herr = asn1.decode(ldap_hex("02 07 20 00 00 00 00 00 00"))
            assert(herr == nil, "2^53 unexpected error: " .. tostring(herr))
            assert(hi == 9007199254740992, "2^53 got " .. tostring(hi))

            local _, lo, lerr = asn1.decode(ldap_hex("02 07 e0 00 00 00 00 00 00"))
            assert(lerr == nil, "-2^53 unexpected error: " .. tostring(lerr))
            assert(lo == -9007199254740992, "-2^53 got " .. tostring(lo))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 4: oversized messageID is rejected by decode_message, not rounded
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local proto = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local big  = "30 12 02 07 20 00 00 00 00 00 01 61 07 0a 01 00 04 00 04 00"
            local near = "30 12 02 07 20 00 00 00 00 00 00 61 07 0a 01 00 04 00 04 00"

            local res, err = proto.decode_message(ldap_hex(big))
            assert(res == nil, "oversized messageID must not decode, got id " ..
                   tostring(res and res.message_id))
            assert(err ~= nil, "oversized messageID must report an error")

            -- Two different wire messageIDs must never correlate to the same in-process id.
            local r1 = proto.decode_message(ldap_hex(big))
            local r2 = proto.decode_message(ldap_hex(near))
            assert(not (r1 and r2 and r1.message_id == r2.message_id),
                   "distinct wire messageIDs collided on " ..
                   tostring(r1 and r1.message_id))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
