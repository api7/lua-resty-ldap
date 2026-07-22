# Test vectors: original; spec X.690 §8.7.1/§8.9.1/§8.11.1.

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

=== TEST 1: primitive universal SEQUENCE/SET must be rejected, not walked
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- Baseline: the constructed forms decode as containers.
            local _, ok_seq = assert(asn1.decode(ldap_hex("30 03 02 01 05")))
            assert(type(ok_seq) == "table" and ok_seq[1] == 5, "constructed SEQUENCE decodes")
            local _, ok_set = assert(asn1.decode(ldap_hex("31 03 02 01 05")))
            assert(type(ok_set) == "table" and ok_set[1] == 5, "constructed SET decodes")

            -- X.690 s8.9.1/s8.11.1: SEQUENCE/SET always constructed; 0x10/0x11 are illegal
            local _, v1, e1 = asn1.decode(ldap_hex("10 03 02 01 05"))
            assert(v1 == nil, "primitive SEQUENCE (0x10) yields no value, got " .. tostring(v1))
            assert(e1 ~= nil, "primitive SEQUENCE (0x10) reports an error")

            local _, v2, e2 = asn1.decode(ldap_hex("11 03 02 01 05"))
            assert(v2 == nil, "primitive SET (0x11) yields no value, got " .. tostring(v2))
            assert(e2 ~= nil, "primitive SET (0x11) reports an error")

            -- empty primitive container: while loop never runs, returns {} silently
            local _, v3, e3 = asn1.decode(ldap_hex("10 00"))
            assert(v3 == nil, "empty primitive SEQUENCE yields no value")
            assert(e3 ~= nil, "empty primitive SEQUENCE reports an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 2: the constructed check must not tighten accepted BER length leniency
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- guard rail: constructed-bit check must not reject BER non-minimal lengths
            local _, v1 = assert(asn1.decode(ldap_hex("30 81 03 02 01 05")))
            assert(type(v1) == "table" and v1[1] == 5, "non-minimal-length SEQUENCE still decodes")

            local _, v2 = assert(asn1.decode(ldap_hex("31 81 03 04 01 41")))
            assert(type(v2) == "table" and v2[1] == "A", "non-minimal-length SET still decodes")

            local _, v3 = assert(asn1.decode(ldap_hex("04 81 03 41 42 43")))
            assert(v3 == "ABC", "non-minimal-length OCTET STRING still decodes, got " .. tostring(v3))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 3: primitive containers reached through decode_message must be rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- SearchResultEntry: dn "a", attribute "cn" with one value "x"
            local function entry(pal, pa, set)
                return "30 15 02 01 02 64 10 04 01 61 " .. pal .. " 0b " .. pa
                       .. " 09 04 02 63 6e " .. set .. " 03 04 01 78"
            end

            local ok = assert(protocol.decode_message(ldap_hex(entry("30", "30", "31"))))
            assert(ok.entry_dn == "a", "baseline entry_dn")
            assert(ok.attributes.cn[1] == "x", "baseline attribute value")

            -- each flips one container to primitive; PAL/PA bypass decode_children
            local cases = {
                { "10", "30", "31", "PartialAttributeList primitive (0x10)" },
                { "30", "10", "31", "PartialAttribute primitive (0x10)" },
                { "30", "30", "11", "vals SET OF primitive (0x11)" },
                { "10", "10", "11", "every container primitive" },
            }
            for _, c in ipairs(cases) do
                local res, err = protocol.decode_message(ldap_hex(entry(c[1], c[2], c[3])))
                assert(res == nil, c[4] .. " must be rejected, got cn="
                                   .. tostring(res and res.attributes
                                               and res.attributes.cn
                                               and res.attributes.cn[1]))
                assert(err ~= nil, c[4] .. " reports an error")
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
