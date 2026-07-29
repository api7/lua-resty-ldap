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
                ldap_host  = "127.0.0.1",
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
                ldap_host  = "127.0.0.1",
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



=== TEST 3: verification is on when tls_verify is unset
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            -- no tls_verify key at all, and no lua_ssl_trusted_certificate
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_host = "127.0.0.1",
                ldap_port = 1636,
                ldaps     = true,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok == nil, "an unset tls_verify must still verify: " ..
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
                ldap_host  = "127.0.0.1",
                ldap_port  = 1636,
                ldaps      = true,
                tls_verify = false,
                base_dn    = "ou=users,dc=example,dc=org",
                attribute  = "cn",
            })
            assert(ok, "unverified handshake should bind: " .. tostring(err))

            -- the first call pools its socket under :noverify, so the
            -- verifying call cannot draw it and needs a fresh handshake, which
            -- fails: no trusted certificate is configured
            local ok2, err2 = ldap.ldap_authenticate("user01", "password1", {
                ldap_host  = "127.0.0.1",
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



=== TEST 8: a missing ldap_host is a config error, never a bind against localhost
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok == nil, "a missing ldap_host must not authenticate, got " .. tostring(ok))
            assert(err == "ldap_host is required", "unexpected err: " .. tostring(err))

            -- an empty string is the same misconfiguration, set rather than omitted
            local ok2, err2 = ldap.ldap_authenticate("user01", "password1", {
                ldap_host = "",
                ldap_port = 1389,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok2 == nil, "an empty ldap_host must not authenticate, got " .. tostring(ok2))
            assert(err2 == "ldap_host is required", "unexpected err: " .. tostring(err2))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 9: a missing base_dn is a config error, never a bind under a placeholder DN
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            -- the directory really does hold ou=users,dc=example,dc=org, so a
            -- placeholder default would authenticate under a DN never configured
            local ok, err = ldap.ldap_authenticate("user01", "password1", {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                attribute = "cn",
            })
            assert(ok == nil, "a missing base_dn must not authenticate, got " .. tostring(ok))
            assert(err == "base_dn is required", "unexpected err: " .. tostring(err))

            -- an empty base_dn would bind under "cn=user01," and be reported as
            -- a credential failure rather than the misconfiguration it is
            local ok2, err2 = ldap.ldap_authenticate("user01", "password1", {
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                base_dn   = "",
                attribute = "cn",
            })
            assert(ok2 == nil, "an empty base_dn must not authenticate, got " .. tostring(ok2))
            assert(err2 == "base_dn is required", "unexpected err: " .. tostring(err2))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]


=== TEST 10: an invalid password is reported without opening a socket
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require("resty.ldap")
            -- port 1 has no listener: a socket error here instead of the
            -- validation message means the bind connected before checking
            local ok, err = ldap.ldap_authenticate("user01", true, {
                ldap_host = "127.0.0.1",
                ldap_port = 1,
                base_dn   = "ou=users,dc=example,dc=org",
                attribute = "cn",
            })
            assert(ok == false, "a non-string password must be rejected (false), got " ..
                                tostring(ok))
            assert(err == "bind password must be a string", "unexpected err: " .. tostring(err))
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
