use Test::Nginx::Socket::Lua;

log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;lib/?/init.lua;/usr/local/share/lua/5.3/?.lua;/usr/share/lua/5.1/?.lua;;';
    resolver 127.0.0.53;
_EOC_

run_tests();

__DATA__

=== TEST 1: anonymous auth (simple bind with empty dn and password)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require "resty.ldap.client"

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
            local ldap_client = require "resty.ldap.client"

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
            local ldap_client = require "resty.ldap.client"

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
Error: The supplied credential is invalid
--- error_code: 401



=== TEST 4: ldaps
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require "resty.ldap.client"

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
            local ldap_client = require "resty.ldap.client"

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
            local ldap_client = require "resty.ldap.client"

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



=== TEST 7: connection reuse
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require "resty.ldap.client"

            local client1 = ldap_client:new("127.0.0.1", 1389, {
                pool_name = "ldap-test"
            })
            client1:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1") -- will trigger the setkeepalive

            local client2 = ldap_client:new("127.0.0.1", 1389, {
                pool_name = "ldap-test"
            })
            client2:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1")

            local client3 = ldap_client:new("127.0.0.1", 1389, {
                pool_name = "ldap-test"
            })

            local client4 = ldap_client:new("127.0.0.1", 1389, {
                pool_name = "ldap-test2"
            })

            local count1 = client3.socket:getreusedtimes()
            assert(count1 == 2, "socket in ldap-test reuse count not equal to 2, actual " .. count1)

            local count2 = client4.socket:getreusedtimes()
            assert(count2 == 0, "socket in ldap-test2 reuse count not equal to 0, actual " .. count2)
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200
