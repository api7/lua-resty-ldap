# Test vectors: rasn v0.6.1 (tagged_boolean).

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

=== TEST 1: decode() dispatches on tag NUMBER only -- full class x P/C matrix
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- every decoder tag x 4 classes x P/C: only universal correct-form yields a value
            local UNIV, APPL, CTXT, PRIV = 0x00, 0x40, 0x80, 0xc0
            local payload = {
                [2]  = { prim = "01 05",        cons = "03 02 01 05" },
                [4]  = { prim = "03 41 42 43",  cons = "05 04 03 41 42 43" },
                [10] = { prim = "01 07",        cons = "03 0a 01 07" },
                [16] = { prim = "03 04 01 41",  cons = "03 04 01 41" },
                [17] = { prim = "03 04 01 41",  cons = "03 04 01 41" },
            }
            local names = { [2]="INTEGER", [4]="OCTET_STRING", [10]="ENUMERATED",
                            [16]="SEQUENCE", [17]="SET" }
            local cnames = { [UNIV]="UNIVERSAL", [APPL]="APPLICATION",
                             [CTXT]="CONTEXT", [PRIV]="PRIVATE" }

            local leaks = {}
            for _, tn in ipairs({2, 4, 10, 16, 17}) do
                for _, cls in ipairs({UNIV, APPL, CTXT, PRIV}) do
                    for _, consbit in ipairs({0x00, 0x20}) do
                        local id   = tn + cls + consbit
                        local cons = consbit == 0x20
                        local hex  = string.format("%02x ", id) ..
                                     (cons and payload[tn].cons or payload[tn].prim)
                        -- SEQUENCE/SET must be constructed; the scalar types primitive
                        local want_ok = (cls == UNIV) and
                            (((tn == 16 or tn == 17) and cons) or
                             ((tn == 2 or tn == 4 or tn == 10) and not cons))

                        local _, v, err = asn1.decode(ldap_hex(hex))
                        local got_ok = (err == nil and v ~= nil)
                        if got_ok ~= want_ok then
                            table.insert(leaks, string.format(
                                "%s %s %s (id=%02x) want_%s got value=%s err=%s",
                                names[tn], cnames[cls], cons and "cons" or "prim", id,
                                want_ok and "value" or "error",
                                type(v) == "table" and "<table>" or tostring(v),
                                tostring(err)))
                        end
                    end
                end
            end

            if #leaks > 0 then
                ngx.say(#leaks .. " class/form mismatches accepted:")
                ngx.say(table.concat(leaks, "\n"))
            else
                ngx.say("ok")
            end
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: tightening class dispatch must not break legal universal encodings
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local asn1 = require("resty.ldap.asn1")
            local ldap_hex = require("ldap_hex")

            -- Guard rail for the class fix: these must all keep working.
            local _, v = asn1.decode(ldap_hex("04 03 41 42 43"))
            assert(v == "ABC", "universal OCTET STRING: " .. tostring(v))
            local _, i = asn1.decode(ldap_hex("02 01 05"))
            assert(i == 5, "universal INTEGER: " .. tostring(i))
            local _, e = asn1.decode(ldap_hex("0a 01 07"))
            assert(e == 7, "universal ENUMERATED: " .. tostring(e))
            local _, s = asn1.decode(ldap_hex("30 03 04 01 41"))
            assert(type(s) == "table" and s[1] == "A", "universal SEQUENCE")
            local _, t = asn1.decode(ldap_hex("31 03 04 01 41"))
            assert(type(t) == "table" and t[1] == "A", "universal SET")

            -- BER non-minimal length still accepted: real directory servers emit it
            local _, nm = asn1.decode(ldap_hex("04 81 03 41 42 43"))
            assert(nm == "ABC", "non-minimal length must still decode: " .. tostring(nm))
            local _, nm2 = asn1.decode(ldap_hex("30 81 03 04 01 41"))
            assert(type(nm2) == "table" and nm2[1] == "A", "non-minimal SEQUENCE length")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: LDAPMessage envelope and messageID must be universal types
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- baseline BindResponse still decodes
            local ok_res = assert(protocol.decode_message(
                ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(ok_res.message_id == 1, "baseline message_id")

            -- envelope tag 16 but primitive (0x10): cons bit unchecked, walks as SEQUENCE
            local r1, e1 = protocol.decode_message(
                ldap_hex("10 0c 02 01 01 61 07 0a 01 00 04 00 04 00"))
            assert(r1 == nil, "primitive envelope 0x10 must be rejected")
            assert(e1 ~= nil, "primitive envelope reports an error")

            -- messageID is INTEGER; context-specific [4] currently yields the string "A"
            local r2, e2 = protocol.decode_message(
                ldap_hex("30 0c 84 01 41 61 07 0a 01 00 04 00 04 00"))
            assert(r2 == nil, "messageID as context [4] must be rejected, got message_id="
                              .. tostring(r2 and r2.message_id))
            assert(e2 ~= nil, "context messageID reports an error")

            -- messageID as context-specific [16]: currently yields a table
            local r3, e3 = protocol.decode_message(
                ldap_hex("30 0b 90 00 61 07 0a 01 00 04 00 04 00"))
            assert(r3 == nil, "messageID as context [16] must be rejected, got type="
                              .. type(r3 and r3.message_id))
            assert(e3 ~= nil, "context [16] messageID reports an error")

            -- messageID as BOOLEAN (no decoder) currently succeeds with message_id == nil
            local r4, e4 = protocol.decode_message(
                ldap_hex("30 0c 01 01 ff 61 07 0a 01 00 04 00 04 00"))
            assert(r4 == nil, "BOOLEAN messageID must be rejected, got message_id="
                              .. tostring(r4 and r4.message_id))
            assert(e4 ~= nil, "BOOLEAN messageID reports an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: LDAPResult fields reject class-mismatched elements
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- BindResponse is parsed pre-auth; resultCode ENUMERATED, matchedDN/diag OCTET STRING
            local cases = {
                { "resultCode as context [4]",      "30 0c 02 01 01 61 07 84 01 41 04 00 04 00" },
                { "resultCode as context [16]",     "30 0b 02 01 01 61 06 90 00 04 00 04 00" },
                { "resultCode as private [17]",     "30 0b 02 01 01 61 06 f1 00 04 00 04 00" },
                { "resultCode as BOOLEAN",          "30 0c 02 01 01 61 07 01 01 ff 04 00 04 00" },
                { "resultCode as NULL",             "30 0b 02 01 01 61 06 05 00 04 00 04 00" },
                { "matchedDN as private [16]",      "30 0c 02 01 01 61 07 0a 01 00 d0 00 04 00" },
                { "diagnosticMessage as appl [4]",  "30 0d 02 01 01 61 08 0a 01 00 04 00 44 01 41" },
            }

            local leaks = {}
            for _, c in ipairs(cases) do
                local res, err = protocol.decode_message(ldap_hex(c[2]))
                if res ~= nil or err == nil then
                    table.insert(leaks, string.format(
                        "%s accepted (result_code=%s/%s matched_dn=%s diag=%s)",
                        c[1],
                        type(res and res.result_code) == "table" and "<table>"
                            or tostring(res and res.result_code),
                        type(res and res.result_code),
                        type(res and res.matched_dn),
                        type(res and res.diagnostic_msg)))
                end
            end

            -- callers concatenate result_code into an error string, so its type must be guaranteed
            local good = assert(protocol.decode_message(
                ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(type(good.result_code) == "number", "result_code is a number")
            assert(type(good.matched_dn) == "string", "matched_dn is a string")
            assert(type(good.diagnostic_msg) == "string", "diagnostic_msg is a string")

            if #leaks > 0 then
                ngx.say(#leaks .. " LDAPResult class confusions accepted:")
                ngx.say(table.concat(leaks, "\n"))
            else
                ngx.say("ok")
            end
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: SearchResultEntry -- hostile server controls the attribute type tag
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- baseline: objectName "x", attribute "s" with an empty vals SET
            local base = assert(protocol.decode_message(
                ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(base.entry_dn == "x", "baseline entry_dn")
            assert(type(base.attributes.s) == "table", "baseline vals is an array")

            -- protocol.lua:228-232 type-checks none of these; the decoded type becomes a table key
            local cases = {
                -- attribute type as context-specific [4]: currently keys as "s"
                { "attr type as context [4]",
                  "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 84 01 73 31 00" },
                -- attribute type as context-specific [16]: currently a TABLE key
                { "attr type as context [16]",
                  "30 10 02 01 03 64 0b 04 01 78 30 06 30 04 90 00 31 00" },
                -- attr type BOOLEAN decodes to nil; `attributes[nil] = vals` raises
                { "attr type as BOOLEAN",
                  "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 01 01 ff 31 00" },
                -- vals as context [4]: attributes.s becomes a STRING, not an array
                { "vals as context [4]",
                  "30 14 02 01 03 64 0f 04 01 78 30 0a 30 08 04 01 73 84 03 41 42 43" },
                -- objectName as private [16]: entry_dn becomes a table
                { "objectName as private [16]",
                  "30 10 02 01 03 64 0b d0 00 30 07 30 05 04 01 73 31 00" },
            }

            local leaks = {}
            for _, c in ipairs(cases) do
                -- pcall: a malformed packet must return (nil, err), never throw
                local pok, res, err = pcall(protocol.decode_message, ldap_hex(c[2]))
                if not pok then
                    table.insert(leaks, c[1] .. " RAISED a Lua error: " .. tostring(res))
                elseif res ~= nil or err == nil then
                    local ktypes = {}
                    for k, v in pairs(res.attributes or {}) do
                        table.insert(ktypes, type(k) .. "->" .. type(v))
                    end
                    table.insert(leaks, string.format(
                        "%s accepted (entry_dn=%s attributes=[%s])",
                        c[1], type(res.entry_dn), table.concat(ktypes, ",")))
                end
            end

            if #leaks > 0 then
                ngx.say(#leaks .. " SearchResultEntry class confusions:")
                ngx.say(table.concat(leaks, "\n"))
            else
                ngx.say("ok")
            end
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: SearchResultEntry container tags are not validated at all
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- parse_search_entry uses only .offset/.len, so any tag walks as a SEQUENCE
            local cases = {
                -- PartialAttributeList sent as a primitive OCTET STRING
                { "attribute list as OCTET STRING 04",
                  "30 11 02 01 03 64 0c 04 01 78 04 07 30 05 04 01 73 31 00" },
                -- PartialAttribute sent as a primitive OCTET STRING
                { "PartialAttribute as OCTET STRING 04",
                  "30 11 02 01 03 64 0c 04 01 78 30 07 04 05 04 01 73 31 00" },
                -- vals SET sent APPLICATION-class primitive
                { "vals SET as application [17]",
                  "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 51 00" },
            }

            local leaks = {}
            for _, c in ipairs(cases) do
                local res, err = protocol.decode_message(ldap_hex(c[2]))
                if res ~= nil or err == nil then
                    table.insert(leaks, c[1] .. " accepted")
                end
            end

            if #leaks > 0 then
                ngx.say(#leaks .. " container tag confusions accepted:")
                ngx.say(table.concat(leaks, "\n"))
            else
                ngx.say("ok")
            end
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: SearchResultReference URIs must be universal OCTET STRINGs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- baseline
            local base = assert(protocol.decode_message(
                ldap_hex("30 0f 02 01 02 73 0a 04 08 6c 64 61 70 3a 2f 2f 78")))
            assert(base.uris[1] == "ldap://x", "baseline uri")

            -- RFC 4511: URIs are universal OCTET STRINGs; a class-confused URI steers a referral
            local r1, e1 = protocol.decode_message(
                ldap_hex("30 0f 02 01 02 73 0a 84 08 6c 64 61 70 3a 2f 2f 78"))
            assert(r1 == nil, "context [4] URI must be rejected, got "
                              .. tostring(r1 and r1.uris[1]))
            assert(e1 ~= nil, "context [4] URI reports an error")

            -- context [16] members currently come back as tables inside uris
            local r2, e2 = protocol.decode_message(ldap_hex("30 09 02 01 02 73 04 90 00 90 00"))
            assert(r2 == nil, "context [16] URI must be rejected, got "
                              .. type(r2 and r2.uris and r2.uris[1]))
            assert(e2 ~= nil, "context [16] URI reports an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
