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

            local client = ldap_client:new("127.0.0.1", 1636, { ldaps = true })
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

            local client = ldap_client:new("127.0.0.1", 1389, { start_tls = true })
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

            -- pool a connection established without certificate verification
            local a = ldap_client:new("localhost", 1636, { ldaps = true, ssl_verify = false })
            assert(a:connect())
            assert(a.socket:getreusedtimes() == 0, "first connection must be fresh")
            assert(a:set_keepalive())

            -- ssl_verify=true must not reuse it (a fresh connection is required)
            local b = ldap_client:new("localhost", 1636, { ldaps = true, ssl_verify = true })
            assert(b:connect())
            assert(b.socket:getreusedtimes() == 0,
                   "an unverified pooled connection must not serve ssl_verify=true")
            assert(b:set_keepalive())

            -- control: the same policy does reuse its own pooled connection
            local c = ldap_client:new("localhost", 1636, { ldaps = true, ssl_verify = false })
            assert(c:connect())
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

            local a = ldap_client:new("localhost", 1389, { start_tls = true, ssl_verify = false })
            assert(a:connect())
            assert(a.socket:getreusedtimes() == 0, "first connection must be fresh")
            assert(a:set_keepalive())

            local b = ldap_client:new("localhost", 1389, { start_tls = true, ssl_verify = true })
            assert(b:connect())
            assert(b.socket:getreusedtimes() == 0,
                   "an unverified pooled STARTTLS connection must not serve ssl_verify=true")
            assert(b:set_keepalive())

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
            client.pinned = true

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



=== TEST 11: a single-shot bind never returns its socket to the shared pool
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local protocol = require("resty.ldap.protocol")

            -- control: an unbound single-shot search does re-enter the pool
            local a = ldap_client:new("127.0.0.1", 1389)
            assert(a:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)"))
            local b = ldap_client:new("127.0.0.1", 1389)
            assert(b:connect())
            assert(b.socket:getreusedtimes() > 0, "unbound search should hit the pool")
            assert(b:set_keepalive())

            -- a single-shot admin bind checks out the pooled socket, binds on
            -- it, and must close it on release instead of pooling it again
            local c = ldap_client:new("127.0.0.1", 1389)
            assert(c:simple_bind("cn=admin,dc=example,dc=org", "adminpassword"))

            -- a new anonymous client must get a fresh connection; its search
            -- must not inherit the admin identity
            local d = ldap_client:new("127.0.0.1", 1389)
            assert(d:connect())
            assert(d.socket:getreusedtimes() == 0,
                   "admin-bound socket leaked into the pool")
            local res, serr = d:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil, "(objectClass=*)")
            assert(res, "anonymous search: " .. tostring(serr))
            assert(#res == 1, "one entry")
            assert(d:set_keepalive())

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 12: ldap_authenticate never pools a socket that carried a bind
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

            -- a failed bind closes its socket instead of pooling it; the pool
            -- is observable as the default host:port pool
            local ok = ldap.ldap_authenticate("user01", "wrong-password", conf)
            assert(ok == false, "a wrong password must be rejected (false), got " .. tostring(ok))
            local probe = ngx.socket.tcp()
            assert(probe:connect("127.0.0.1", 1389))
            assert(probe:getreusedtimes() == 0,
                   "failed-bind socket leaked into the pool")
            probe:close()

            -- a successful bind leaves the socket holding the user's identity,
            -- so it too must be closed, never pooled
            local ok2, err2 = ldap.ldap_authenticate("user01", "password1", conf)
            assert(ok2, "authenticate failed: " .. tostring(err2))
            local probe2 = ngx.socket.tcp()
            assert(probe2:connect("127.0.0.1", 1389))
            assert(probe2:getreusedtimes() == 0,
                   "user-bound socket leaked into the pool")
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
            client.pinned = true

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
            client.pinned = true

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
