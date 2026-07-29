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

=== TEST 1: anonymous auth (simple bind with empty dn and password)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:simple_bind()
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 2: simple bind auth (ok)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 3: simple bind auth (invalid credential)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:simple_bind("cn=user01,ou=users,dc=example,dc=org", "invalid_password")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- error_log
simple bind failed, error: The supplied credential is invalid
--- error_code: 401



=== TEST 4: ldaps
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("127.0.0.1", 1636, { ldaps = true, ssl_verify = false })
            local res, err = client:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 5: starttls
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("127.0.0.1", 1389, { start_tls = true, ssl_verify = false })
            local res, err = client:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 6: ldaps (verify server certificate)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        lua_ssl_trusted_certificate ../../certs/mycacert.crt;
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("localhost", 1636, { ldaps = true, ssl_verify = true })
            local res, err = client:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200


=== TEST 7: resty.ldap.ldap_authenticate binds a valid user
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok, "authenticate failed: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 8: a pooled unverified TLS connection is never reused with verification on
--- http_config eval: $::HttpConfig
--- config
    location /t {
        lua_ssl_trusted_certificate ../../certs/mycacert.crt;
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local function anon_search(c)
                return c:search("dc=example,dc=org",
                    protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            end

            -- pool a connection established without certificate verification
            local a = ldap_client:new("localhost", 1636, { ldaps = true, ssl_verify = false })
            assert(anon_search(a))
            assert(a.socket:getreusedtimes() == 0, "first connection must be fresh")
            assert(a:set_keepalive())

            -- ssl_verify=true must not reuse it (a fresh connection is required)
            local b = ldap_client:new("localhost", 1636, { ldaps = true, ssl_verify = true })
            assert(anon_search(b))
            assert(b.socket:getreusedtimes() == 0,
                   "an unverified pooled connection must not serve ssl_verify=true")
            assert(b:set_keepalive())

            -- control: the same policy does reuse its own pooled connection
            local c = ldap_client:new("localhost", 1636, { ldaps = true, ssl_verify = false })
            assert(anon_search(c))
            assert(c.socket:getreusedtimes() > 0, "same-policy reuse should hit the pool")
            assert(c:set_keepalive())

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 9: starttls pools are partitioned by verification policy too
--- http_config eval: $::HttpConfig
--- config
    location /t {
        lua_ssl_trusted_certificate ../../certs/mycacert.crt;
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            local function anon_search(c)
                return c:search("dc=example,dc=org",
                    protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            end

            local a = ldap_client:new("localhost", 1389, { start_tls = true, ssl_verify = false })
            assert(anon_search(a))
            assert(a.socket:getreusedtimes() == 0, "first connection must be fresh")
            assert(a:set_keepalive())

            local b = ldap_client:new("localhost", 1389, { start_tls = true, ssl_verify = true })
            assert(anon_search(b))
            assert(b.socket:getreusedtimes() == 0,
                   "an unverified pooled STARTTLS connection must not serve ssl_verify=true")
            assert(b:set_keepalive())

            -- control: the same policy does reuse its own pooled connection
            local c = ldap_client:new("localhost", 1389, { start_tls = true, ssl_verify = false })
            assert(anon_search(c))
            assert(c.socket:getreusedtimes() > 0, "same-policy reuse should hit the pool")
            assert(c:set_keepalive())

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 10: client returns a controlled error when a response header contains a 0x00 byte
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local closed, step = false, 0
            local sock = {
                send    = function(_, p) return #p end,
                receive = function()
                    step = step + 1
                    if step == 1 then
                        return "\48\00" -- header: SEQUENCE tag, then a 0x00 length octet
                    end
                    return "" -- the declared zero-length body
                end,
                close   = function() closed = true return true end,
            }

            local client = ldap_client:new("127.0.0.1", 1389)
            client.socket = sock

            local res, err = client:simple_bind(
                "cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "a 0x00 header byte must be a transport failure (nil), got " ..
                               tostring(res))
            assert(err:find("failed to decode ldap message", 1, true),
                   "unexpected err: " .. tostring(err))
            assert(closed, "the unusable socket must be closed")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 11: a single-shot bind pools apart from the anonymous pool
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            -- prime the anonymous pool: an unbound search re-enters it on release
            local a = ldap_client:new("127.0.0.1", 1389)
            assert(a:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))
            assert(a:set_keepalive())

            -- an admin bind draws from the bind pool, which is still empty, so it
            -- opens its own connection and leaves the anonymous one alone
            local b = ldap_client:new("127.0.0.1", 1389)
            assert(b:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))
            assert(b:set_keepalive())

            -- exactly one checkout behind the anonymous socket. Had the bind
            -- borrowed it this would be 2 (pooled back) or 0 (closed), and
            -- either way the search below could inherit the admin identity.
            local c = ldap_client:new("127.0.0.1", 1389)
            local res, serr = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "anonymous search: " .. tostring(serr))
            assert(c.socket:getreusedtimes() == 1,
                   "a bind must not draw from the anonymous pool, got " ..
                   c.socket:getreusedtimes())
            assert(#res == 1, "one entry")
            assert(c:set_keepalive())

            -- the bind pool did keep its socket, so the next bind reuses it
            local probe = ngx.socket.tcp()
            assert(probe:connect("127.0.0.1", 1389, { pool = "127.0.0.1:1389:bind" }))
            assert(probe:getreusedtimes() > 0, "the bound socket was not pooled")
            probe:close()

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 12: ldap_authenticate reuses the bind pool and never the anonymous one
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            local conf = {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            }

            -- the first call opens a connection, the second reuses it: one
            -- socket, two binds on it
            local ok, err = ldap.ldap_authenticate("user01", "password1", conf)
            assert(ok, "authenticate failed: " .. tostring(err))
            local ok2, err2 = ldap.ldap_authenticate("user01", "password1", conf)
            assert(ok2, "authenticate failed: " .. tostring(err2))

            local probe = ngx.socket.tcp()
            assert(probe:connect("127.0.0.1", 1389, { pool = "127.0.0.1:1389:bind" }))
            assert(probe:getreusedtimes() == 2,
                   "the second authenticate should have reused the pooled socket, got " ..
                   probe:getreusedtimes())
            probe:close()

            -- a rejected bind leaves the session anonymous (RFC 4513 s4), so its
            -- socket is poolable too, and the next call still rebinds on it
            local ok3 = ldap.ldap_authenticate("user01", "wrong-password", conf)
            assert(ok3 == false, "a wrong password must be rejected (false), got " .. tostring(ok3))
            local ok4, err4 = ldap.ldap_authenticate("user01", "password1", conf)
            assert(ok4, "a reused socket must still authenticate: " .. tostring(err4))

            -- and none of those sockets ever entered the anonymous pool, where an
            -- unbound search would have picked up a user's identity
            local probe2 = ngx.socket.tcp()
            assert(probe2:connect("127.0.0.1", 1389))
            assert(probe2:getreusedtimes() == 0,
                   "a bound socket leaked into the anonymous pool")
            probe2:close()

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 13: client returns a controlled error when the response header is unreadable
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local closed = false
            local sock = {
                send    = function(_, p) return #p end,
                receive = function() return nil, "timeout" end,
                close   = function() closed = true return true end,
            }

            local client = ldap_client:new("127.0.0.1", 1389)
            client.socket = sock

            local res, err = client:simple_bind(
                "cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "a receive timeout must be a transport failure (nil), got " ..
                               tostring(res))
            assert(err:find("receive response failed", 1, true),
                   "unexpected err: " .. tostring(err))
            assert(closed, "the unusable socket must be closed")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 14: client returns a controlled error when the response body is truncated
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local closed, step = false, 0
            local sock = {
                send    = function(_, p) return #p end,
                receive = function()
                    step = step + 1
                    if step == 1 then
                        return "\48\05" -- header: SEQUENCE tag, body length 5
                    end
                    return nil, "closed" -- body read fails
                end,
                close   = function() closed = true return true end,
            }

            local client = ldap_client:new("127.0.0.1", 1389)
            client.socket = sock

            local res, err = client:simple_bind(
                "cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "a truncated body must be a transport failure (nil), got " ..
                               tostring(res))
            assert(err:find("receive response failed", 1, true),
                   "unexpected err: " .. tostring(err))
            assert(closed, "the unusable socket must be closed")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 15: an invalid bind dn/password is reported without opening a socket
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            -- port 1 has no listener: a socket error here instead of the
            -- validation message means simple_bind connected before checking
            local client = ldap_client:new("127.0.0.1", 1)

            local res, err = client:simple_bind({}, "password1")
            assert(res == false, "table dn must fail")
            assert(err == "bind dn must be a string", "got: " .. tostring(err))

            local res2, err2 = client:simple_bind("cn=user01", true)
            assert(res2 == false, "boolean password must fail")
            assert(err2 == "bind password must be a string", "got: " .. tostring(err2))

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 16: a dropped connection before any response is a reported failure
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            -- a pooled socket the server has already dropped reads "closed",
            -- not "timeout", on the very first header read
            local closed = false
            local sock = {
                send    = function(_, p) return #p end,
                receive = function() return nil, "closed" end,
                close   = function() closed = true return true end,
            }

            local client = ldap_client:new("127.0.0.1", 1389)
            client.socket = sock

            local res, err = client:simple_bind(
                "cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "a dropped connection must be a transport failure (nil)")
            assert(err ~= nil, "it must carry a diagnostic, got nil")
            assert(err:find("receive response failed", 1, true),
                   "unexpected err: " .. tostring(err))
            assert(closed, "the unusable socket must be closed")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 17: a search cut short before SearchResultDone must fail, not return partial results
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_hex = require("ldap_hex")

            -- one complete SearchResultEntry, then the peer goes away without
            -- ever sending SearchResultDone
            local entry = ldap_hex("30 16 02 01 03 64 11 04 01 78" ..
                                   " 30 0c 30 0a 04 01 73 31 05 04 03 01 00 02")
            local step, closed = 0, false
            local sock = {
                send    = function(_, p) return #p end,
                receive = function(_, n)
                    step = step + 1
                    if step == 1 then return entry:sub(1, 2) end
                    if step == 2 then return entry:sub(3) end
                    return nil, "closed"
                end,
                close   = function() closed = true return true end,
            }

            local client = ldap_client:new("127.0.0.1", 1389)
            client.socket = sock

            local res, err = client:search("dc=example,dc=org")
            assert(res == false,
                   "a truncated search must fail; got " .. type(res) ..
                   " with " .. tostring(type(res) == "table" and #res or "n/a") .. " entries")
            assert(err ~= nil, "it must carry a diagnostic, got nil")
            assert(closed, "the unusable socket must be closed")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 18: an omitted ssl_verify verifies the server certificate
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            -- no ssl_verify key, and no lua_ssl_trusted_certificate to satisfy it
            local client = ldap_client:new("127.0.0.1", 1636, { ldaps = true })
            local res, err = client:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "an omitted ssl_verify must still verify, got " .. tostring(res))
            assert(err:find("TLS handshake", 1, true), "unexpected err: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
certificate verify error
