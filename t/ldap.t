use Test::Nginx::Socket::Lua;

log_level('info');
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;lib/?/init.lua;/usr/local/share/lua/5.3/?.lua;/usr/share/lua/5.1/?.lua;;';
_EOC_

run_tests();

__DATA__

=== TEST 1: auth ok
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap = require "resty.ldap"
            local ldapconf = {
                timeout = 10000,
                start_tls = false,
                ldap_host = "127.0.0.1",
                ldap_port = 1389,
                ldaps = false,
                verify_ldap_host = false,
                base_dn = "ou=users,dc=example,dc=org",
                attribute = "cn",
                keepalive = 60000,
            }
            local res, err = ldap.ldap_authenticate("john", "abc", ldapconf)
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
