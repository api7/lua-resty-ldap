# Test vectors: original, RFC 4511 protocolOp tags — https://www.rfc-editor.org/rfc/rfc4511.txt

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

=== TEST 1: a protocolOp that is not a decodable response must error, never fabricate an LDAPResult
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- Each body is a valid LDAPResult; only the protocolOp tag varies -- non-response ops must be refused
            local cases = {
                -- [APPLICATION 30] constructed: unassigned in RFC 4511
                {"unassigned op 30", "30 0c 02 01 01 7e 07 0a 01 00 04 00 04 00"},
                -- request-side PDUs a server must never send (UnbindRequest is NULL, RFC 4511 s4.3)
                {"BindRequest op 0",    "30 0c 02 01 01 60 07 0a 01 00 04 00 04 00"},
                {"UnbindRequest op 2",  "30 0c 02 01 01 62 07 0a 01 00 04 00 04 00"},
                {"SearchRequest op 3",  "30 0c 02 01 01 63 07 0a 01 00 04 00 04 00"},
                {"ExtendedRequest op 23", "30 0c 02 01 01 77 07 0a 01 00 04 00 04 00"},
                -- primitive [APPLICATION 1]: every protocolOp is a SEQUENCE, so this is malformed
                {"primitive BindResponse", "30 0c 02 01 01 41 07 0a 01 00 04 00 04 00"},
            }

            for _, c in ipairs(cases) do
                local ok, res, err = pcall(protocol.decode_message, ldap_hex(c[2]))
                assert(ok, c[1] .. ": decode_message raised instead of returning an error: " .. tostring(res))
                assert(res == nil,
                       c[1] .. ": must be rejected, but decoded to result_code=" ..
                       tostring(type(res) == "table" and res.result_code or "?"))
                assert(type(err) == "string" and #err > 0, c[1] .. ": missing error message")
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



=== TEST 2: the allowlist must not overreach -- all six response ops the library supports still decode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local APP = protocol.APP_NO
            local ldap_hex = require("ldap_hex")

            local ldap_result = {
                {"BindResponse",    APP.BindResponse,    "30 0c 02 01 01 61 07 0a 01 00 04 00 04 00"},
                {"SearchResultDone", APP.SearchResultDone, "30 0c 02 01 02 65 07 0a 01 00 04 00 04 00"},
                {"ModifyResponse",  APP.ModifyResponse,  "30 0c 02 01 02 67 07 0a 01 00 04 00 04 00"},
                {"ExtendedResponse", APP.ExtendedResponse, "30 0c 02 01 01 78 07 0a 01 00 04 00 04 00"},
            }
            for _, c in ipairs(ldap_result) do
                local res, err = protocol.decode_message(ldap_hex(c[3]))
                assert(res, c[1] .. ": must still decode, got: " .. tostring(err))
                assert(res.protocol_op == c[2], c[1] .. ": op " .. tostring(res.protocol_op))
                assert(res.result_code == 0, c[1] .. ": result_code " .. tostring(res.result_code))
                assert(res.matched_dn == "" and res.diagnostic_msg == "", c[1] .. ": LDAPResult fields")
            end

            local e, eerr = protocol.decode_message(ldap_hex("30 0a 02 01 03 64 05 04 01 78 30 00"))
            assert(e, "SearchResultEntry must still decode, got: " .. tostring(eerr))
            assert(e.protocol_op == APP.SearchResultEntry and e.entry_dn == "x", "entry")
            -- a real entry carries no LDAPResult, so none may be invented for it
            assert(e.result_code == nil, "SearchResultEntry must not carry a result_code")

            local r, rerr = protocol.decode_message(ldap_hex("30 0f 02 01 02 73 0a 04 08 6c 64 61 70 3a 2f 2f 78"))
            assert(r, "SearchResultReference must still decode, got: " .. tostring(rerr))
            assert(r.protocol_op == APP.SearchResultReference, "ref op")
            assert(r.uris and r.uris[1] == "ldap://x", "ref uri")
            assert(r.result_code == nil, "SearchResultReference must not carry a result_code")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
