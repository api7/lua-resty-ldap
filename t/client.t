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
