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

=== TEST 1: BindResponse success (LDAPResult shape)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- 30 0c 02 01 01 61 07 0a 01 00 04 00 04 00  (reference 6.1)
            local res = assert(protocol.decode_message(h("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(res.protocol_op == protocol.APP_NO.BindResponse, "op " .. res.protocol_op)
            assert(res.result_code == 0, "code")
            assert(res.matched_dn == "", "matched_dn")
            assert(res.diagnostic_msg == "", "diag")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: SearchResultEntry, multi-valued attribute stays an array
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- reference 4.5 worked 75-byte entry
            local pkt = h([[30 49 02 01 02 64 44
                04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 63 6f 6d
                30 2f
                   30 1c 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73
                         31 0d 04 03 74 6f 70 04 06 64 6f 6d 61 69 6e
                   30 0f 04 02 64 63
                         31 09 04 07 65 78 61 6d 70 6c 65]])
            local res = assert(protocol.decode_message(pkt))
            assert(res.protocol_op == protocol.APP_NO.SearchResultEntry, "op")
            assert(res.entry_dn == "dc=example,dc=com", "entry_dn " .. tostring(res.entry_dn))
            assert(type(res.attributes.objectClass) == "table", "objectClass is array")
            assert(#res.attributes.objectClass == 2, "objectClass count")
            assert(res.attributes.objectClass[1] == "top", "oc[1]")
            assert(res.attributes.objectClass[2] == "domain", "oc[2]")
            assert(#res.attributes.dc == 1 and res.attributes.dc[1] == "example", "dc single value still array")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: binary attribute value with embedded NUL is not truncated
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- entry_dn "x", attribute "s" = single value bytes 01 00 02
            local res = assert(protocol.decode_message(h(
                "30 16 02 01 03 64 11 04 01 78 30 0c 30 0a 04 01 73 31 05 04 03 01 00 02")))
            assert(res.entry_dn == "x", "dn")
            assert(#res.attributes.s == 1, "one value")
            assert(#res.attributes.s[1] == 3, "value length " .. #res.attributes.s[1])  -- 3, not 1
            assert(res.attributes.s[1] == "\1\0\2", "value bytes")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 4: empty vals SET and empty attribute list
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- entry_dn "x", one attribute "s" with EMPTY vals set (typesOnly): 31 00
            local res = assert(protocol.decode_message(h(
                "30 11 02 01 03 64 0c 04 01 78 30 07 30 05 04 01 73 31 00")))
            assert(type(res.attributes.s) == "table", "s is table")
            assert(#res.attributes.s == 0, "s empty")
            -- entry with EMPTY attribute list: attrs 30 00
            local res2 = assert(protocol.decode_message(h("30 0a 02 01 03 64 05 04 01 78 30 00")))
            assert(res2.entry_dn == "x", "dn2")
            assert(next(res2.attributes) == nil, "no attributes")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 5: SearchResultReference decodes URIs (op 19)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- msgID 2, ref with one URI "ldap://x"
            local res = assert(protocol.decode_message(h("30 0f 02 01 02 73 0a 04 08 6c 64 61 70 3a 2f 2f 78")))
            assert(res.protocol_op == protocol.APP_NO.SearchResultReference, "op " .. res.protocol_op)
            assert(#res.uris == 1, "uri count")
            assert(res.uris[1] == "ldap://x", "uri")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 6: SearchResultDone with nonzero code; malformed envelope errors
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end
            -- SearchResultDone noSuchObject(32=0x20)
            local res = assert(protocol.decode_message(h("30 0c 02 01 02 65 07 0a 01 20 04 00 04 00")))
            assert(res.protocol_op == protocol.APP_NO.SearchResultDone, "op")
            assert(res.result_code == 32, "code " .. res.result_code)
            -- not an LDAPMessage SEQUENCE
            local bad, err = protocol.decode_message(h("04 01 41"))
            assert(bad == nil and err ~= nil, "malformed rejected")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 7: a field may not overrun the enclosing operation's boundary
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local function h(s) return (s:gsub("%s+",""):gsub("%x%x", function(b) return string.char(tonumber(b,16)) end)) end

            -- BindResponse declares 2 content bytes; its resultCode TLV is 4 and
            -- runs into matchedDN, decoding as a "successful" result_code 256
            local bad, err = protocol.decode_message(h("30 0d 02 01 01 61 02 0a 02 01 00 04 00 04 00"))
            assert(bad == nil, "resultCode overrunning the op is rejected")
            assert(err ~= nil, "resultCode overrunning the op reports an error")

            -- ref declares 2 content bytes; the 10-byte URI TLV lies outside it
            local bad2, err2 = protocol.decode_message(h("30 0f 02 01 02 73 02 04 08 6c 64 61 70 3a 2f 2f 78"))
            assert(bad2 == nil and err2 ~= nil, "URI overrunning the op is rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
