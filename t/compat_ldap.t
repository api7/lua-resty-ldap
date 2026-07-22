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

=== TEST 1: tls_verify=true enforces certificate verification
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            -- no lua_ssl_trusted_certificate, so verifying the test CA must fail
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_host  = "localhost",
                ldap_port  = 1636,
                ldaps      = true,
                tls_verify = true,
                base_dn    = "ou=users,dc=example,dc=org",
                attribute  = "cn",
            })
            assert(ok == false, "verification should have failed the handshake")
            assert(err:find("SSL handshake", 1, true), "unexpected err: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
lua tls certificate verify error



=== TEST 2: tls_verify=false skips verification and binds
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_host  = "localhost",
                ldap_port  = 1636,
                ldaps      = true,
                tls_verify = false,
                base_dn    = "ou=users,dc=example,dc=org",
                attribute  = "cn",
            })
            assert(ok, "handshake without verification should bind: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 3: verify_ldap_host=true is honoured as a legacy alias for tls_verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_host        = "localhost",
                ldap_port        = 1636,
                ldaps            = true,
                verify_ldap_host = true,
                base_dn          = "ou=users,dc=example,dc=org",
                attribute        = "cn",
            })
            assert(ok == false, "legacy verify_ldap_host should have enforced verification")
            assert(err:find("SSL handshake", 1, true), "unexpected err: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
lua tls certificate verify error



=== TEST 4: bind_request on a dead socket fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap.ldap")

            local sock = ngx.socket.tcp()
            sock:settimeout(10000)
            assert(sock:connect("127.0.0.1", 1389))
            sock:close() -- kill the connection underneath bind_request

            local res, err = ldap.bind_request(sock,
                "cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "a dead socket must fail, got " .. tostring(res))
            assert(err ~= nil, "a dead socket must report an error")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
attempt to send data on a closed socket



=== TEST 5: bind_request returns a controlled error when the response header is unreadable
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap.ldap")

            local closed = false
            local sock = {
                send    = function(_, p) return #p end,
                receive = function() return nil, "timeout" end,
                close   = function() closed = true return true end,
            }

            local res, err = ldap.bind_request(sock,
                "cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "a receive timeout must fail, got " .. tostring(res))
            assert(err ~= nil, "a receive timeout must report an error")
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



=== TEST 6: bind_request returns a controlled error when the response body is truncated
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap.ldap")

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

            local res, err = ldap.bind_request(sock,
                "cn=user01,ou=users,dc=example,dc=org", "password1")
            assert(res == nil, "a truncated body must fail, got " .. tostring(res))
            assert(err ~= nil, "a truncated body must report an error")
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



=== TEST 7: ldap_authenticate rejects usernames with DN metacharacters
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            -- a real port, but the metacharacter check must reject before connecting
            local ok, err = ldap.ldap_authenticate("al,ice", "password1", {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok == false, "a metacharacter username must be rejected")
            assert(err == "username contains characters not allowed in a bind DN",
                   "unexpected err: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 8: ldap_authenticate binds a valid user with the raw DN
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



=== TEST 9: a wrong password is a clean auth failure
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            local ok, err = ldap.ldap_authenticate("user01", "wrong-password", {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok == false, "a wrong password must fail")
            assert(err:find("credential", 1, true), "expected a credential error: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
