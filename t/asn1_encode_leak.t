# Test vectors: original — FFI heap ownership, no upstream analogue.

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

=== TEST 1: the i2d_* encoders must not leak the buffer OpenSSL allocates for them
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")

            -- i2d with NULL *pp makes OpenSSL malloc a buffer the encoder must free itself

            local function rss_kb()
                local f = assert(io.open("/proc/self/status"))
                local kb = 0
                for line in f:lines() do
                    local v = line:match("^VmRSS:%s+(%d+) kB")
                    if v then kb = tonumber(v) end
                end
                f:close()
                return kb
            end

            local function growth_mb(n, fn)
                for i = 1, 100 do fn(i) end        -- warm up JIT + allocator
                collectgarbage("collect"); collectgarbage("collect")
                local before = rss_kb()
                for i = 1, n do fn(i) end
                collectgarbage("collect"); collectgarbage("collect")
                return (rss_kb() - before) / 1024
            end

            local SZ  = 4000
            local val = string.rep("A", SZ)

            -- thresholds sit under each encoder's expected leak; small encoders need more iters

            -- Control: the SEQUENCE encoder (ASN1_put_object) allocates nothing
            local control = growth_mb(20000, function()
                return asn1.encode(val, asn1.TAG.SEQUENCE)
            end)
            assert(control < 8,
                   ("control (put_object) path itself grew %.1f MB -- " ..
                    "measurement is unreliable"):format(control))

            -- ~76 MB if every i2d buffer leaked; a correct encoder stays flat
            local octet = growth_mb(20000, function()
                return asn1.encode(val, asn1.TAG.OCTET_STRING)
            end)
            assert(octet < 8,
                   ("i2d_ASN1_OCTET_STRING leaked: RSS grew %.1f MB over " ..
                    "20000 encodes (control %.1f MB)"):format(octet, control))

            -- INTEGER/ENUMERATED leak ~11 bytes/call; ~15 MB at 500000 iters, 4 MB threshold
            local int = growth_mb(500000, function(i)
                return asn1.encode(i, asn1.TAG.INTEGER)
            end)
            assert(int < 4,
                   ("i2d_ASN1_INTEGER leaked: RSS grew %.1f MB over " ..
                    "500000 encodes"):format(int))

            local enum = growth_mb(500000, function(i)
                return asn1.encode(i % 128, asn1.TAG.ENUMERATED)
            end)
            assert(enum < 4,
                   ("i2d_ASN1_ENUMERATED leaked: RSS grew %.1f MB over " ..
                    "500000 encodes"):format(enum))

            -- Freeing must not change a single output byte.
            assert(asn1.encode("A", asn1.TAG.OCTET_STRING) == "\4\1A")
            assert(asn1.encode("", asn1.TAG.OCTET_STRING) == "\4\0")
            assert(asn1.encode(5, asn1.TAG.INTEGER) == "\2\1\5")
            assert(asn1.encode("\0\255\0", asn1.TAG.OCTET_STRING) == "\4\3\0\255\0")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- timeout: 60
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: the leak is reachable from the public request builders
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")

            -- bind/search requests build messageIDs and strings via the leaking encoders

            local function rss_kb()
                local f = assert(io.open("/proc/self/status"))
                local kb = 0
                for line in f:lines() do
                    local v = line:match("^VmRSS:%s+(%d+) kB")
                    if v then kb = tonumber(v) end
                end
                f:close()
                return kb
            end

            local function growth_mb(n, fn)
                for i = 1, 50 do assert(fn(i)) end
                collectgarbage("collect"); collectgarbage("collect")
                local before = rss_kb()
                for i = 1, n do assert(fn(i)) end
                collectgarbage("collect"); collectgarbage("collect")
                return (rss_kb() - before) / 1024
            end

            local dn = "cn=" .. string.rep("u", 1000) .. ",dc=example,dc=com"

            local bind = growth_mb(20000, function(i)
                return protocol.simple_bind_request(dn, "secret", i)
            end)
            assert(bind < 8,
                   ("simple_bind_request leaked: RSS grew %.1f MB over " ..
                    "20000 requests"):format(bind))

            local search = growth_mb(20000, function(i)
                return protocol.search_request(dn, 2, 0, 0, 0, false,
                           "(objectClass=" .. string.rep("x", 500) .. ")",
                           { "cn", "mail", "uid" }, i)
            end)
            assert(search < 8,
                   ("search_request leaked: RSS grew %.1f MB over " ..
                    "20000 requests"):format(search))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- timeout: 60
--- response_body
ok
--- no_error_log
[error]
