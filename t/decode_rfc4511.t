# Test vectors: Go go1.26.3 encoding/asn1 (INTEGER boundary) — https://github.com/golang/go/blob/go1.26.3/src/encoding/asn1/asn1_test.go

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

=== TEST 1: every response type in APP_NO decodes per RFC 4511
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- BindResponse [APPLICATION 1] success (RFC 4511 s4.2.2)
            local r = assert(protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(r.message_id == 1 and r.protocol_op == protocol.APP_NO.BindResponse, "bind op")
            assert(r.result_code == 0, "bind code")

            -- SearchResultDone [APPLICATION 5] (s4.5.2)
            r = assert(protocol.decode_message(ldap_hex("30 0c 02 01 02 65 07 0a 01 00 04 00 04 00")))
            assert(r.protocol_op == protocol.APP_NO.SearchResultDone, "done op " .. r.protocol_op)
            assert(r.result_code == 0, "done code")

            -- ModifyResponse [APPLICATION 7] (s4.6)
            r = assert(protocol.decode_message(ldap_hex("30 0c 02 01 02 67 07 0a 01 00 04 00 04 00")))
            assert(r.protocol_op == protocol.APP_NO.ModifyResponse, "modify op " .. r.protocol_op)
            assert(r.result_code == 0, "modify code")

            -- ExtendedResponse [APPLICATION 24] (s4.12) -- StartTLS reply shape
            r = assert(protocol.decode_message(ldap_hex("30 0c 02 01 01 78 07 0a 01 00 04 00 04 00")))
            assert(r.protocol_op == protocol.APP_NO.ExtendedResponse, "ext op " .. r.protocol_op)
            assert(r.result_code == 0, "ext code")

            -- SearchResultReference [APPLICATION 19] (s4.5.2)
            r = assert(protocol.decode_message(ldap_hex("30 0f 02 01 02 73 0a 04 08 6c 64 61 70 3a 2f 2f 78")))
            assert(r.protocol_op == protocol.APP_NO.SearchResultReference, "ref op")
            assert(#r.uris == 1 and r.uris[1] == "ldap://x", "ref uri")

            r = assert(protocol.decode_message(ldap_hex([[30 2c 02 01 01 61 27 0a 01 31 04 00
                04 20 38 30 30 39 30 33 30 38 3a 20 4c 64 61 70 45 72 72 3a 20
                44 53 49 44 2d 30 43 30 39 30 34 34 45]])))
            assert(r.result_code == 49, "code 49 " .. tostring(r.result_code))
            assert(r.diagnostic_msg == "80090308: LdapErr: DSID-0C09044E", "diag " .. tostring(r.diagnostic_msg))

            r = assert(protocol.decode_message(ldap_hex("30 0c 02 01 00 78 07 0a 01 34 04 00 04 00")))
            assert(r.message_id == 0, "unsolicited messageID must be preserved as 0")
            assert(r.protocol_op == protocol.APP_NO.ExtendedResponse and r.result_code == 52, "notice of disconnection")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: Active-Directory-shaped entry: binary objectSid/objectGUID, non-UTF-8 values
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local pkt = ldap_hex([[
                30 81 cc
                  02 01 03
                  64 81 c6
                    04 26 43 4e 3d 4a 61 6e 65 20 44 6f 65 2c 43 4e 3d 55 73 65 72
                          73 2c 44 43 3d 65 78 61 6d 70 6c 65 2c 44 43 3d 63 6f 6d
                    30 81 9b
                      30 2b 04 09 6f 62 6a 65 63 74 53 69 64
                            31 1e 04 1c 01 05 00 00 00 00 00 05 15 00 00 00 dc f4
                                        dc 3b 83 3d 2b 46 82 8b a6 28 00 02 00 00
                      30 20 04 0a 6f 62 6a 65 63 74 47 55 49 44
                            31 12 04 10 bc c9 3a d0 00 e7 b1 4f b3 91 7d 6f 5c 00
                                        1e a9
                      30 10 04 02 73 6e
                            31 0a 04 08 4d fc 6c 6c 65 72 ff fe
                      30 38 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73
                            31 29 04 03 74 6f 70
                                  04 06 70 65 72 73 6f 6e
                                  04 14 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 61 6c
                                        50 65 72 73 6f 6e
                                  04 04 75 73 65 72]])
            assert(#pkt == 207, "fixture length " .. #pkt)

            local r = assert(protocol.decode_message(pkt))
            assert(r.protocol_op == protocol.APP_NO.SearchResultEntry, "op")
            assert(r.entry_dn == "CN=Jane Doe,CN=Users,DC=example,DC=com", "dn " .. tostring(r.entry_dn))

            local sid = r.attributes.objectSid[1]
            assert(#sid == 28, "objectSid truncated at a NUL: " .. #sid)
            assert(sid == ldap_hex("01 05 00 00 00 00 00 05 15 00 00 00 dc f4 dc 3b 83 3d 2b 46 82 8b a6 28 00 02 00 00"),
                   "objectSid bytes")
            -- the SID must survive byte-for-byte: S-1-5-21-1004336348-1177238915-682003330-512
            assert(sid:byte(1) == 1 and sid:byte(2) == 5, "SID revision/subauth count")

            local guid = r.attributes.objectGUID[1]
            assert(#guid == 16, "objectGUID truncated at a NUL: " .. #guid)
            assert(guid == ldap_hex("bc c9 3a d0 00 e7 b1 4f b3 91 7d 6f 5c 00 1e a9"), "objectGUID bytes")

            -- invalid UTF-8 must pass through untouched, not be replaced or rejected
            local sn = r.attributes.sn[1]
            assert(#sn == 8, "sn length " .. #sn)
            assert(sn == ldap_hex("4d fc 6c 6c 65 72 ff fe"), "non-UTF-8 sn bytes")

            assert(#r.attributes.objectClass == 4, "objectClass count " .. #r.attributes.objectClass)
            assert(r.attributes.objectClass[4] == "user", "objectClass[4]")

            local root = assert(protocol.decode_message(ldap_hex([[30 4d 02 01 03 64 48 04 00 30 44
                30 1b 04 14 73 75 70 70 6f 72 74 65 64 4c 44 41 50 56 65 72 73 69 6f 6e
                      31 03 04 01 33
                30 25 04 0e 6e 61 6d 69 6e 67 43 6f 6e 74 65 78 74 73
                      31 13 04 11 44 43 3d 65 78 61 6d 70 6c 65 2c 44 43 3d 63 6f 6d]])))
            assert(root.entry_dn == "", "root DSE dn must be the empty string, got " .. tostring(root.entry_dn))
            assert(root.attributes.namingContexts[1] == "DC=example,DC=com", "namingContexts")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: optional trailing LDAPResult components are tolerated; only envelope-level trailing bytes are rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local r = assert(protocol.decode_message(ldap_hex([[30 1b 02 01 01 61 16
                0a 01 0a 04 00 04 00
                a3 0d 04 0b 6c 64 61 70 3a 2f 2f 72 2f 78 79]])),
                "BindResponse with referral [3] must parse")
            assert(r.result_code == 10, "referral result code " .. tostring(r.result_code))
            assert(r.matched_dn == "" and r.diagnostic_msg == "", "mandatory fields intact")

            -- SearchResultDone carrying an AD-style referral URI
            r = assert(protocol.decode_message(ldap_hex([[30 34 02 01 02 65 2f
                0a 01 0a 04 00 04 00
                a3 24 04 22 6c 64 61 70 3a 2f 2f 44 6f 6d 61 69 6e 44 6e 73 5a 6f
                            6e 65 73 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 2f 64 63]])),
                "SearchResultDone with referral [3] must parse")
            assert(r.protocol_op == protocol.APP_NO.SearchResultDone and r.result_code == 10, "done+referral")

            r = assert(protocol.decode_message(ldap_hex("30 12 02 01 01 61 0d 0a 01 0e 04 00 04 00 87 04 de ad be ef")),
                "BindResponse with serverSaslCreds [7] must parse")
            assert(r.result_code == 14, "saslBindInProgress " .. tostring(r.result_code))

            r = assert(protocol.decode_message(ldap_hex([[30 29 02 01 01 78 24
                0a 01 00 04 00 04 00
                8a 16 31 2e 33 2e 36 2e 31 2e 34 2e 31 2e 31 34 36 36 2e 32 30 30 33 37
                8b 03 41 42 43]])),
                "ExtendedResponse with responseName/responseValue must parse")
            assert(r.protocol_op == protocol.APP_NO.ExtendedResponse and r.result_code == 0, "ext w/ optionals")

            r = assert(protocol.decode_message(ldap_hex("30 81 0c 02 01 01 61 07 0a 01 00 04 00 04 00")),
                "non-minimal envelope length must still decode")
            assert(r.result_code == 0, "non-minimal envelope result")

            local bad, err = protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00 de ad be ef"))
            assert(bad == nil, "trailing bytes after the envelope must be rejected")
            assert(err ~= nil, "trailing bytes must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: an undecodable SearchResultEntry field must return an error, never raise
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local pkt = ldap_hex("30 11 02 01 03 64 0c 04 01 78 30 07 30 05 01 01 ff 31 00")
            local ok, res, err = pcall(protocol.decode_message, pkt)
            assert(ok, "decode_message raised instead of returning an error: " .. tostring(res))
            assert(res == nil, "undecodable attribute type must not yield a result")
            assert(err ~= nil, "undecodable attribute type must report an error")

            -- non-string AttributeDescription (INTEGER 5) keys attributes by number; must be LDAPString (RFC 4511 s4.1.4)
            local ok2, res2, err2 = pcall(protocol.decode_message,
                ldap_hex("30 14 02 01 03 64 0f 04 01 78 30 0a 30 08 02 01 05 31 03 04 01 41"))
            assert(ok2, "non-string attribute type raised: " .. tostring(res2))
            assert(res2 == nil and err2 ~= nil,
                   "attribute type that is not an LDAPString must be rejected")

            -- objectName that is not an LDAPDN (INTEGER 5) must be an error, not entry_dn == 5
            local ok3, res3, err3 = pcall(protocol.decode_message, ldap_hex("30 0a 02 01 03 64 05 02 01 05 30 00"))
            assert(ok3, "non-string objectName raised: " .. tostring(res3))
            assert(res3 == nil and err3 ~= nil, "objectName must be an LDAPDN, got " .. tostring(res3 and res3.entry_dn))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: a missing resultCode or messageID must fail loudly, not become nil
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(ldap_hex("30 0c 02 01 01 61 07 01 01 ff 04 00 04 00"))
            assert(bad == nil, "resultCode must be a number; got result_code=" ..
                   tostring(bad and bad.result_code))
            assert(err ~= nil, "undecodable resultCode must report an error")

            -- messageID as a BOOLEAN: a nil message_id breaks request/response correlation (RFC 4511 s4.1.1)
            local bad2, err2 = protocol.decode_message(ldap_hex("30 0c 01 01 ff 61 07 0a 01 00 04 00 04 00"))
            assert(bad2 == nil, "messageID must be an INTEGER; got message_id=" ..
                   tostring(bad2 and bad2.message_id))
            assert(err2 ~= nil, "undecodable messageID must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: SearchResultReference must not silently drop an undecodable URI
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(ldap_hex([[30 1c 02 01 02 73 17
                04 08 6c 64 61 70 3a 2f 2f 78
                01 01 ff
                04 08 6c 64 61 70 3a 2f 2f 79]]))
            assert(bad == nil, "reference with an undecodable member must be rejected; got " ..
                   tostring(bad and #bad.uris) .. " uris")
            assert(err ~= nil, "reference with an undecodable member must report an error")

            -- a well-formed multi-URI reference still decodes in full
            local r = assert(protocol.decode_message(ldap_hex([[30 23 02 01 02 73 1e
                04 08 6c 64 61 70 3a 2f 2f 78
                04 08 6c 64 61 70 3a 2f 2f 79
                04 08 6c 64 61 70 3a 2f 2f 7a]])))
            assert(#r.uris == 3, "3 uris, got " .. #r.uris)
            assert(r.uris[3] == "ldap://z", "third uri")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: PartialAttributeList containers must actually be SEQUENCEs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- attributes slot is an OCTET STRING (04) holding a PartialAttribute
            local bad, err = protocol.decode_message(ldap_hex([[30 18 02 01 03 64 13
                04 01 78
                04 0e 30 0c 04 02 63 6e 31 06 04 04 4a 61 6e 65]]))
            assert(bad == nil, "attributes must be a SEQUENCE; OCTET STRING yielded cn=" ..
                   tostring(bad and bad.attributes and bad.attributes.cn and bad.attributes.cn[1]))
            assert(err ~= nil, "non-SEQUENCE attributes list must report an error")

            -- attributes slot is context-specific [16] (b0): same tag number as SEQUENCE, different class
            local bad2, err2 = protocol.decode_message(ldap_hex([[30 14 02 01 03 64 0f
                04 01 78
                b0 0a 30 08 04 02 63 6e 31 02 04 00]]))
            assert(bad2 == nil, "context-specific [16] is not a SEQUENCE")
            assert(err2 ~= nil, "context-specific [16] attributes list must report an error")

            -- an individual PartialAttribute encoded as an OCTET STRING
            local bad3, err3 = protocol.decode_message(ldap_hex([[30 18 02 01 03 64 13
                04 01 78
                30 0e 04 0c 04 02 63 6e 31 06 04 04 4a 61 6e 65]]))
            assert(bad3 == nil, "PartialAttribute must be a SEQUENCE; got cn=" ..
                   tostring(bad3 and bad3.attributes and bad3.attributes.cn and bad3.attributes.cn[1]))
            assert(err3 ~= nil, "non-SEQUENCE PartialAttribute must report an error")

            -- the well-formed equivalent still decodes
            local r = assert(protocol.decode_message(ldap_hex([[30 16 02 01 03 64 11
                04 01 78
                30 0c 30 0a 04 02 63 6e 31 04 04 02 4a 44]])))
            assert(r.attributes.cn[1] == "JD", "well-formed entry still decodes")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 8: an out-of-range messageID must not be silently coerced to -1
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local bad, err = protocol.decode_message(
                ldap_hex("30 14 02 09 00 ff ff ff ff ff ff ff ff 61 07 0a 01 00 04 00 04 00"))
            assert(bad == nil, "out-of-range messageID must be rejected; got message_id=" ..
                   tostring(bad and bad.message_id))
            assert(err ~= nil, "out-of-range messageID must report an error")

            -- a genuine large-but-legal messageID still works: 2147483647 == maxInt
            local r = assert(protocol.decode_message(
                ldap_hex("30 0f 02 04 7f ff ff ff 61 07 0a 01 00 04 00 04 00")))
            assert(r.message_id == 2147483647, "maxInt messageID " .. tostring(r.message_id))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
