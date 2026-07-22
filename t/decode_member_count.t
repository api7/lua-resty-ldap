# Test vectors: pyasn1 v0.6.4 — https://github.com/pyasn1/pyasn1/blob/v0.6.4/tests/codec/ber/test_decoder.py

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

=== TEST 1: a dropped vals member is reachable from decode_message (EOC)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- vals SET holds "a", EOC (00 00), "b"; EOC decodes to silent nil -> must error, not drop
            local res, err = protocol.decode_message(ldap_hex(
                "30 20 02 01 03 64 1b 04 01 78 30 16 30 14 04 08 6d 65 6d 62 65 72 4f 66" ..
                " 31 08 04 01 61 00 00 04 01 62"))

            -- An element that yields no value is an error, not an omission.
            assert(res == nil, "entry with an undecodable vals member must not decode")
            assert(err ~= nil, "an undecodable vals member must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 2: same silent drop via a BOOLEAN member
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- Middle member is BOOLEAN TRUE (01 01 ff): has encoder but no decoder, same silent-nil path
            local res, err = protocol.decode_message(ldap_hex(
                "30 21 02 01 03 64 1c 04 01 78 30 17 30 15 04 08 6d 65 6d 62 65 72 4f 66" ..
                " 31 09 04 01 61 01 01 ff 04 01 62"))

            assert(res == nil, "entry with a BOOLEAN vals member must not decode")
            assert(err ~= nil, "a BOOLEAN vals member must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 3: SearchResultReference URI list drops members too (separate code path)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- parse_search_reference builds uris via its own loop, not decode_children; needs the decode() fix
            local res, err = protocol.decode_message(ldap_hex(
                "30 0d 02 01 02 73 08 04 01 61 00 00 04 01 62"))

            assert(res == nil, "reference with an undecodable URI member must not decode")
            assert(err ~= nil, "an undecodable URI member must report an error")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 4: regression guard -- genuinely empty SETs stay empty, not errors
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- typesOnly zero-member vals SET (31 00) must stay empty, not become an error
            local res = assert(protocol.decode_message(ldap_hex(
                "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(type(res.attributes.s) == "table", "s is an array")
            assert(#res.attributes.s == 0, "s is empty, not an error")

            -- And a well-formed multi-valued SET still returns every member.
            local res2 = assert(protocol.decode_message(ldap_hex(
                "30 1e 02 01 03 64 19 04 01 78 30 14 30 12 04 08 6d 65 6d 62 65 72 4f 66" ..
                " 31 06 04 01 61 04 01 62")))
            assert(#res2.attributes.memberOf == 2, "both members returned")
            assert(res2.attributes.memberOf[1] == "a", "member 1")
            assert(res2.attributes.memberOf[2] == "b", "member 2")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
