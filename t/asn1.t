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

=== TEST 1: get_object reads tag/class/len/hl for short and long form
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end

            -- short form: 30 03 02 01 05  (SEQUENCE len 3)
            local o = assert(asn1.get_object(h("30 03 02 01 05")))
            assert(o.tag == 16, "tag " .. o.tag)          -- SEQUENCE
            assert(o.class == asn1.CLASS.UNIVERSAL, "class")
            assert(o.cons == true, "cons")
            assert(o.len == 3, "len " .. o.len)
            assert(o.hl == 2, "hl " .. o.hl)
            assert(o.offset == 2, "offset " .. o.offset)

            -- long form: 30 81 82 <130 bytes>  (2-extra-byte header)
            local body = string.rep("\0", 130)
            local o2 = assert(asn1.get_object(h("30 81 82") .. body))
            assert(o2.len == 130, "long len " .. o2.len)
            assert(o2.hl == 3, "long hl " .. o2.hl)       -- NOT 2

            -- application-tagged: 64 00  (SearchResultEntry, empty)
            local o3 = assert(asn1.get_object(h("64 00")))
            assert(o3.tag == 4, "app tag " .. o3.tag)
            assert(o3.class == asn1.CLASS.APPLICATION, "app class")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: decode octet string is NUL-safe (regression: no strlen truncation)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- 04 05 41 42 00 43 44  => "AB\0CD" (5 bytes, embedded NUL)
            local _, v = asn1.decode(h("04 05 41 42 00 43 44"))
            assert(#v == 5, "length " .. #v)               -- would be 2 under the old strlen bug
            assert(v == "AB\0CD", "value")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: decode integer, enumerated, and nested SEQUENCE/SET (uses hl, not +2)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end

            local _, id = asn1.decode(h("02 01 03"))
            assert(id == 3, "int " .. tostring(id))
            local _, code = asn1.decode(h("0a 01 00"))
            assert(code == 0, "enum " .. tostring(code))

            -- SET OF two octet strings: 31 0d 04 03 746f70 04 06 646f6d61696e
            local _, vals = asn1.decode(h("31 0d 04 03 74 6f 70 04 06 64 6f 6d 61 69 6e"))
            assert(type(vals) == "table", "set is table")
            assert(vals[1] == "top" and vals[2] == "domain", "set values")

            -- long-form SET (>=128 bytes of content) parses via hl, not +2
            local big = string.rep("\4\1X", 60)          -- 60 octet strings "X" = 180 bytes
            local seq = h("31 81 b4") .. big              -- 0xb4 = 180
            local _, arr = asn1.decode(seq)
            assert(#arr == 60, "long set count " .. #arr)
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: malformed input returns error, never crashes
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- claims 5 content bytes, only 2 present
            local off, v, err = asn1.decode(h("30 05 02 01"))
            assert(v == nil, "no value on malformed")
            assert(err ~= nil, "error reported")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: decoder errors surface, not swallowed as empty success
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end

            -- truncated child inside a SEQUENCE: outer len 3, inner OCTET
            -- STRING claims 5 content bytes but only 1 present
            local _, v, err = asn1.decode(h("30 03 04 05 41"))
            assert(v == nil, "no value for truncated child")
            assert(err ~= nil, "truncated child reports error")

            -- zero-length INTEGER: d2i_ASN1_INTEGER returns nil
            local _, v2, err2 = asn1.decode(h("02 00"))
            assert(v2 == nil, "no value for zero-len INTEGER")
            assert(err2 ~= nil, "zero-len INTEGER reports error")

            -- zero-length ENUMERATED: d2i_ASN1_ENUMERATED returns nil
            local _, v3, err3 = asn1.decode(h("0a 00"))
            assert(v3 == nil, "no value for zero-len ENUMERATED")
            assert(err3 ~= nil, "zero-len ENUMERATED reports error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
