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

=== TEST 1: basic search
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require "resty.ldap.client"

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search("dc=example,dc=org")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res > 0, "result is empty")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



