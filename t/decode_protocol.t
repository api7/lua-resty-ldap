# Test vectors: original, hand-built from RFC 4511 grammar — https://www.rfc-editor.org/rfc/rfc4511.txt

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

=== TEST 1: an unrecognized protocolOp must not be parsed as an LDAPResult
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- [APPLICATION 30] is unassigned in RFC 4511
            local bad, err = protocol.decode_message(ldap_hex("30 0c 02 01 01 7e 07 0a 01 00 04 00 04 00"))
            assert(bad == nil, "unassigned app tag 30 must not yield an LDAPResult")
            assert(err ~= nil, "unassigned app tag 30 must report an error")

            -- UnbindRequest [APPLICATION 2]: client->server NULL-body PDU (RFC 4511 s4.3), never result_code 0
            local bad2, err2 = protocol.decode_message(ldap_hex("30 0c 02 01 01 62 07 0a 01 00 04 00 04 00"))
            assert(bad2 == nil, "UnbindRequest must not be reported as result_code 0")
            assert(err2 ~= nil, "UnbindRequest must report an error")

            -- SearchRequest [APPLICATION 3], likewise a request PDU
            local bad3, err3 = protocol.decode_message(ldap_hex("30 0c 02 01 01 63 07 0a 01 00 04 00 04 00"))
            assert(bad3 == nil and err3 ~= nil, "SearchRequest must not decode as a result")

            -- primitive APPLICATION [1] is not well-formed; every protocolOp is constructed
            local bad4, err4 = protocol.decode_message(ldap_hex("30 0c 02 01 01 41 07 0a 01 00 04 00 04 00"))
            assert(bad4 == nil and err4 ~= nil, "primitive APPLICATION op must be rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: every real LDAPResult-shaped op still decodes (allowlist must not overreach)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local cases = {
                { "61", protocol.APP_NO.BindResponse },
                { "65", protocol.APP_NO.SearchResultDone },
                { "67", protocol.APP_NO.ModifyResponse },
                { "78", protocol.APP_NO.ExtendedResponse },
            }
            for _, c in ipairs(cases) do
                local pkt = ldap_hex("30 0c 02 01 01 " .. c[1] .. " 07 0a 01 00 04 00 04 00")
                local res, err = protocol.decode_message(pkt)
                assert(res ~= nil, "op 0x" .. c[1] .. " must decode: " .. tostring(err))
                assert(res.protocol_op == c[2], "op 0x" .. c[1] .. " tag")
                assert(res.result_code == 0, "op 0x" .. c[1] .. " result_code")
            end

            local res = assert(protocol.decode_message(
                ldap_hex("30 81 0d 02 01 01 61 81 07 0a 01 00 04 00 04 00")))
            assert(res.protocol_op == protocol.APP_NO.BindResponse, "non-minimal op")
            assert(res.result_code == 0, "non-minimal result_code")
            assert(res.matched_dn == "" and res.diagnostic_msg == "", "non-minimal fields")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: LDAPResult fields must have the right ASN.1 types
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 01 01 ff 04 00 04 00"))
            assert(bad == nil, "non-numeric resultCode must not produce a result table")
            assert(err ~= nil, "non-numeric resultCode must report an error")

            -- OCTET STRING resultCode becomes "\0", compares ~= 0, so a successful bind reads as failure
            local bad2, err2 = protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 04 01 00 04 00 04 00"))
            assert(bad2 == nil and err2 ~= nil, "OCTET STRING resultCode must be rejected")

            -- matchedDN slot holds an INTEGER: matched_dn becomes the number 5
            local bad3, err3 = protocol.decode_message(ldap_hex("30 0d 02 01 01 61 08 0a 01 00 02 01 05 04 00"))
            assert(bad3 == nil and err3 ~= nil, "non-string matchedDN must be rejected")

            -- messageID is INTEGER (RFC 4511 s4.1.1); an OCTET STRING here yields message_id == "A"
            local bad4, err4 = protocol.decode_message(ldap_hex("30 0c 04 01 41 61 07 0a 01 00 04 00 04 00"))
            assert(bad4 == nil and err4 ~= nil, "non-integer messageID must be rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: a non-string attribute type must error, never index the table with nil
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local pkt = ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 30 05 01 01 ff 31 00")
            local ok, res, err = pcall(protocol.decode_message, pkt)
            assert(ok, "decode_message must not raise: " .. tostring(res))
            assert(res == nil, "nil attribute type must not produce a result")
            assert(err ~= nil, "nil attribute type must report an error")

            -- `type` is an INTEGER -> a numeric key lands in the attributes table
            local pkt2 = ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 30 05 02 01 07 31 00")
            local ok2, res2, err2 = pcall(protocol.decode_message, pkt2)
            assert(ok2, "decode_message must not raise on numeric type")
            assert(res2 == nil and err2 ~= nil, "numeric attribute type must be rejected")

            -- objectName is an LDAPDN (OCTET STRING); an INTEGER here yields entry_dn == 9
            local bad3, err3 = protocol.decode_message(ldap_hex("30 0a 02 01 03 64 05 02 01 09 30 00"))
            assert(bad3 == nil and err3 ~= nil, "non-string objectName must be rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: PartialAttributeList and PartialAttribute must be constructed SEQUENCEs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(
                ldap_hex("30 14 02 01 03 64 0f 04 01 78 04 0a 30 08 04 01 73 31 03 04 01 61"))
            assert(bad == nil, "PartialAttributeList must be a constructed SEQUENCE")
            assert(err ~= nil, "non-SEQUENCE attribute list must report an error")

            -- primitive OCTET STRING walked as if it were a PartialAttribute SEQUENCE
            local bad2, err2 = protocol.decode_message(
                ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 04 05 04 01 73 31 00"))
            assert(bad2 == nil, "PartialAttribute must be a constructed SEQUENCE")
            assert(err2 ~= nil, "non-SEQUENCE PartialAttribute must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: attribute values are always an array (vals must be a SET)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(
                ldap_hex("30 12 02 01 03 64 0d 04 01 78 30 08 30 06 04 01 73 04 01 41"))
            assert(bad == nil, "vals that is not a SET must be rejected")
            assert(err ~= nil, "non-SET vals must report an error")

            -- well-formed shape and typesOnly empty SET still work (SET wrapping adds 2 bytes per level)
            local ok1 = assert(protocol.decode_message(
                ldap_hex("30 14 02 01 03 64 0f 04 01 78 30 0a 30 08 04 01 73 31 03 04 01 41")))
            assert(type(ok1.attributes.s) == "table" and ok1.attributes.s[1] == "A", "well-formed vals")
            local ok2 = assert(protocol.decode_message(
                ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(type(ok2.attributes.s) == "table" and #ok2.attributes.s == 0, "empty vals SET")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: a repeated attribute type still decodes to a well-formed attribute map
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- PartialAttributeList carries "uid" twice: {"a"} then {"b"}
            local pkt = ldap_hex([[30 22 02 01 03 64 1d
                04 01 78
                30 18
                   30 0a 04 03 75 69 64 31 03 04 01 61
                   30 0a 04 03 75 69 64 31 03 04 01 62]])
            local res, err = protocol.decode_message(pkt)
            assert(res ~= nil, "duplicate attribute type must decode: " .. tostring(err))
            assert(res.entry_dn == "x", "entry_dn")
            local uid = res.attributes.uid
            assert(type(uid) == "table", "uid must be an array, got " .. type(uid))
            assert(#uid == 1 and (uid[1] == "a" or uid[1] == "b"),
                   "uid must hold one of the values actually sent")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 8: bytes left over after a parsed element are never ignored
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(ldap_hex("30 0d 02 01 03 64 08 04 01 78 30 00 04 01 5a"))
            assert(bad == nil, "trailing bytes inside SearchResultEntry must be rejected")
            assert(err ~= nil, "trailing bytes inside the op must report an error")

            -- same at the envelope level: the LDAPMessage SEQUENCE must consume the whole packet
            local bad2, err2 = protocol.decode_message(
                ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00 de ad be ef"))
            assert(bad2 == nil, "trailing bytes after the envelope must be rejected")
            assert(err2 ~= nil, "trailing bytes after the envelope must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 9: SearchResultReference URIs are never silently dropped or non-strings
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(ldap_hex("30 0c 02 01 02 73 07 01 01 ff 04 02 6f 6b"))
            assert(bad == nil, "an undecodable referral element must not vanish")
            assert(err ~= nil, "an undecodable referral element must report an error")

            -- nested SEQUENCE lands a table in uris[1]; URI (RFC 4511 s4.1.10) is an OCTET STRING on the wire
            local bad2, err2 = protocol.decode_message(ldap_hex("30 09 02 01 02 73 04 30 02 04 00"))
            assert(bad2 == nil, "non-string referral URI must be rejected")
            assert(err2 ~= nil, "non-string referral URI must report an error")

            -- well-formed referrals still decode
            local ok1 = assert(protocol.decode_message(
                ldap_hex("30 0f 02 01 02 73 0a 04 08 6c 64 61 70 3a 2f 2f 78")))
            assert(#ok1.uris == 1 and ok1.uris[1] == "ldap://x", "well-formed referral")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
