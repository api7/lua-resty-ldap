use Test::Nginx::Socket::Lua;

log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'deps/share/lua/5.1/?.lua;/usr/share/lua/5.1/?.lua;;';
    lua_package_cpath 'deps/lib/lua/5.1/?.so;;';
    resolver 127.0.0.53;
_EOC_

run_tests();

__DATA__

=== TEST 1: basic search
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search()
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



=== TEST 2: basic search (in non-exist tree)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search("dc=example,dc=com")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- error_log
search failed, error: No such object
--- error_code: 401



=== TEST 3: search scope (SEARCH_SCOPE_BASE_OBJECT)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                ldap_protocol.SEARCH_SCOPE_BASE_OBJECT, nil, nil, nil, nil,
                "(objectClass=*)"
            )
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "dc=example,dc=org", "result entryDN is not equal to dc=example,dc=org")
            assert(#res[1].attributes.objectClass == 2, "result objectClass length is not equal to 2")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 4: search scope (SEARCH_SCOPE_SINGLE_LEVEL)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                ldap_protocol.SEARCH_SCOPE_SINGLE_LEVEL, nil, nil, nil, nil,
                "(objectClass=*)"
            )
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "ou=users,dc=example,dc=org", "result 1 entryDN is not equal to ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 5: search scope (SEARCH_SCOPE_WHOLE_SUBTREE)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                ldap_protocol.SEARCH_SCOPE_WHOLE_SUBTREE, nil, nil, nil, nil,
                "(objectClass=posixAccount)"
            )
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 2, "result length is not equal to 2")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result 1 entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
            assert(res[2].entryDN == "cn=user02,ou=users,dc=example,dc=org", "result 2 entryDN is not equal to cn=user02,ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 6: search size limit (limit to 1, and exceeded)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, 1, nil, nil,
                "(objectClass=posixAccount)"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end
        }
    }
--- request
GET /t
--- error_log
search failed, error: Size limit exceeded
--- error_code: 401



=== TEST 7: search size limit (limit to 1, and no exceeded)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, 1, nil, nil,
                "(&(objectClass=posixAccount)(uid=user01))"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 8: search time limit (limit to 1, and no exceeded)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, 1, nil,
                "(&(objectClass=posixAccount)(uid=user01))"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 9: search type only (set to true)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, true,
                "(&(objectClass=posixAccount)(uid=user01))", {"uid"}
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(#res[1].attributes.uid == 0, "result uid attribute is not empty")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 9: search type only (set to false)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, false,
                "(&(objectClass=posixAccount)(uid=user01))", {"uid"}
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].attributes.uid == "user01", "result uid attribute is not equal to user01")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 10: search filter (or)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, nil,
                "(|(&(objectClass=posixAccount)(uid=user02))(&(objectClass=posixAccount)(uid=user01)))", {"uid"}
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 2, "result length is not equal to 2")
            assert(res[1].attributes.uid == "user01", "result 1 uid attribute is not equal to user02")
            assert(res[2].attributes.uid == "user02", "result 2 uid attribute is not equal to user01")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 11: search filter (and & not)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, nil,
                "(&(!(objectClass=posixAccount))(!(objectClass=organizationalUnit))(!(objectClass=groupOfNames)))"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "dc=example,dc=org", "result entryDN is not equal to dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 11: search filter (substring#1)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, nil,
                "(&(objectClass=posixAccount)(uid=user*))"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 2, "result length is not equal to 2")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result 1 entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
            assert(res[2].entryDN == "cn=user02,ou=users,dc=example,dc=org", "result 2 entryDN is not equal to cn=user02,ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 12: search filter (approx)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, nil,
                "(&(objectClass=posixAccount)(uid~=user0))"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 2, "result length is not equal to 2")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result 1 entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
            assert(res[2].entryDN == "cn=user02,ou=users,dc=example,dc=org", "result 2 entryDN is not equal to cn=user02,ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 13: search filter (greater)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, nil,
                "(&(objectClass=posixAccount)(uidNumber>=1001))"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "cn=user02,ou=users,dc=example,dc=org", "result entryDN is not equal to cn=user02,ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 14: search filter (less)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                nil, nil, nil, nil, nil,
                "(&(objectClass=posixAccount)(uidNumber<=1000))"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 15: search filter (present)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                ldap_protocol.SEARCH_SCOPE_WHOLE_SUBTREE, nil, nil, nil, nil,
                "(objectClass=*)"
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 5, "result length is not equal to 5")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 16: search attributes
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                ldap_protocol.SEARCH_SCOPE_WHOLE_SUBTREE, nil, nil, nil, nil,
                "(uid=user01)", {"gidNumber"}
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
            assert(res[1].attributes.gidNumber == "1000", "result gidNumber attribute is not equal to 1000")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 17: add new Chinese attribute to user01
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)

            -- auth
            local res, err = client:simple_bind("cn=admin,dc=example,dc=org", "adminpassword")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(res, "failed to bind admin")

            -- modify
            local res, err = client:unknown(
                "304b02012266460424636e3d7573657230312c6f753d75736572732c64633d6578616d706c652c64633d6f7267301e301c0a01003017040b646973706c61794e616d6531080406e4b8ade69687", -- hex
                false
            )
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(res.protocol_op == 7, "protocol_op is not equal to 7, " .. res.protocol_op)
            assert(res.result_code == 0, "result_code is not equal to 0, " .. res.result_code)
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 18: search filter (attribute value in Chinese)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)
            local res, err = client:search(
                "dc=example,dc=org",
                ldap_protocol.SEARCH_SCOPE_WHOLE_SUBTREE, nil, nil, nil, nil,
                "(displayName=中文)", {"gidNumber"}
            )

            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(#res == 1, "result length is not equal to 1")
            assert(res[1].entryDN == "cn=user01,ou=users,dc=example,dc=org", "result entryDN is not equal to cn=user01,ou=users,dc=example,dc=org")
            assert(res[1].attributes.gidNumber == "1000", "result gidNumber attribute is not equal to 1000")
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 19: remove Chinese attribute in user01
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ldap_client = require("resty.ldap.client")
            local ldap_protocol = require("resty.ldap.protocol")

            local client = ldap_client:new("127.0.0.1", 1389)

            -- auth
            local res, err = client:simple_bind("cn=admin,dc=example,dc=org", "adminpassword")
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(res, "failed to bind admin")

            -- modify
            local res, err = client:unknown(
                "304b02014066460424636e3d7573657230312c6f753d75736572732c64633d6578616d706c652c64633d6f7267301e301c0a01013017040b646973706c61794e616d6531080406e4b8ade69687", -- hex
                false
            )
            if not res then
                ngx.log(ngx.ERR, err)
                ngx.exit(401)
            end

            assert(res.protocol_op == 7, "protocol_op is not equal to 7, " .. res.protocol_op)
            assert(res.result_code == 0, "result_code is not equal to 0, " .. res.result_code)
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200
