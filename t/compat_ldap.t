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
            assert(ok == nil, "a rejected handshake must be a transport failure (nil), got " ..
                              tostring(ok))
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
            assert(ok == nil, "legacy verify_ldap_host must enforce verification: " ..
                              "expected a transport failure (nil), got " .. tostring(ok))
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



=== TEST 4: a DN-metacharacter username is escaped into the bind DN
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            -- "al,ice" must reach the server as cn=al\,ice and fail as a clean
            -- credential error; sent raw, the server would refuse the DN itself
            local ok, err, user_dn = ldap.ldap_authenticate("al,ice", "password1", {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok == false, "an unknown escaped username must be rejected (false), got " ..
                                tostring(ok))
            assert(err:find("credential", 1, true),
                   "expected a credential error: " .. tostring(err))
            assert(user_dn == "cn=al\\,ice,ou=users,dc=example,dc=org",
                   "expected the escaped bind DN, got: " .. tostring(user_dn))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 5: ldap_authenticate binds a valid user with the raw DN
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            local ok, err, user_dn = ldap.ldap_authenticate("user01", "password1", {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok, "authenticate failed: " .. tostring(err))
            assert(user_dn == "cn=user01,ou=users,dc=example,dc=org",
                   "expected the canonical bind DN, got: " .. tostring(user_dn))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 6: a wrong password is a clean auth failure
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
            assert(ok == false, "a wrong password must be rejected (false), got " .. tostring(ok))
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



=== TEST 7: an earlier unverified call never lets a tls_verify=true call skip verification
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")

            -- authenticate with verification disabled first
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_host  = "localhost",
                ldap_port  = 1636,
                ldaps      = true,
                tls_verify = false,
                base_dn    = "ou=users,dc=example,dc=org",
                attribute  = "cn",
            })
            assert(ok, "unverified handshake should bind: " .. tostring(err))

            -- whatever state the first call left behind (it must not pool its
            -- bound socket), a verifying call needs a fresh handshake, which
            -- fails: no trusted certificate is configured
            local ok2, err2 = ldap.ldap_authenticate("user01", "password1", {
                ldap_host  = "localhost",
                ldap_port  = 1636,
                ldaps      = true,
                tls_verify = true,
                base_dn    = "ou=users,dc=example,dc=org",
                attribute  = "cn",
            })
            assert(ok2 == nil, "the unverified call must not satisfy a verifying one: " ..
                               "expected a transport failure (nil), got " .. tostring(ok2))
            assert(err2:find("TLS handshake", 1, true), "unexpected err: " .. tostring(err2))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- error_log
certificate verify error
