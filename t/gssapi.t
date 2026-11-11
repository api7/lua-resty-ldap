use Test::Nginx::Socket::Lua;

# End-to-end SASL/GSSAPI binds against a real KDC and slapd. Start them with
#   eval "$(t/gssapi/env.sh start)"
# which exports the variables below; without them this file is skipped.
if (!$ENV{TEST_LDAP_GSSAPI_HOST} || !$ENV{KRB5CCNAME}) {
    plan(skip_all => "no GSSAPI test environment (see t/gssapi/env.sh)");
} else {
    plan 'no_plan';
}

log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);

our $MainConfig = <<'_EOC_';
    env KRB5_CONFIG;
    env KRB5CCNAME;
    env TEST_LDAP_GSSAPI_HOST;
    env TEST_LDAP_GSSAPI_PORT;
_EOC_

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;t/lib/?.lua;/usr/share/lua/5.1/?.lua;;';
    lua_package_cpath 'deps/lib/lua/5.1/?.so;;';
    init_by_lua_block {
        HOST = os.getenv("TEST_LDAP_GSSAPI_HOST")
        -- cosockets cannot resolve names without a resolver; HOST is only
        -- needed for the service principal
        ADDR = os.getenv("TEST_LDAP_GSSAPI_ADDR") or "127.0.0.1"
        PORT = tonumber(os.getenv("TEST_LDAP_GSSAPI_PORT"))
        SERVICE = "ldap@" .. HOST
        USER_DN = "uid=user01,ou=users,dc=example,dc=org"

        -- user01's entry is readable only by user01 (see t/gssapi/env.sh), so
        -- finding it proves the session is bound as user01
        function sees_self(c)
            local protocol = require("resty.ldap.protocol")
            local res, err = c:search("dc=example,dc=org",
                protocol.SEARCH_SCOPE_WHOLE_SUBTREE, nil, nil, nil, nil,
                "(uid=user01)", { "uid" })
            assert(res, "search: " .. tostring(err))
            return #res == 1 and res[1].entry_dn == USER_DN
        end
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: gssapi_bind authenticates as the ticket's principal
--- main_config eval: $::MainConfig
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local client = require("resty.ldap.client")

            local anon = client:new(ADDR, PORT)
            assert(not sees_self(anon), "an anonymous session must not see the entry")
            assert(anon:close())

            local c = client:new(ADDR, PORT)
            local ok, err = c:gssapi_bind(SERVICE)
            assert(ok == true, "bind: " .. tostring(err))
            assert(sees_self(c), "the bound session must see the entry")
            assert(c:close())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 2: a pooled connection is rebound, whatever its previous identity
--- main_config eval: $::MainConfig
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local client = require("resty.ldap.client")

            local c = client:new(ADDR, PORT, { keepalive_pool_name = "gssapi-t2" })
            assert(c:gssapi_bind(SERVICE))
            assert(c:set_keepalive())

            -- the same pooled connection, bound again
            local ok, err = c:gssapi_bind(SERVICE)
            assert(ok == true, "rebind: " .. tostring(err))
            assert(c.socket:getreusedtimes() >= 1, "connection was reused")
            assert(sees_self(c), "still bound as user01")

            -- an anonymous simple bind resets the session (RFC 4513 s4)...
            assert(c:simple_bind())
            assert(not sees_self(c), "anonymous after simple bind")

            -- ...and a GSSAPI bind on the same connection restores it
            assert(c:gssapi_bind(SERVICE))
            assert(sees_self(c), "bound again")
            assert(c:close())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 3: an unknown service principal fails before anything is sent
--- main_config eval: $::MainConfig
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local client = require("resty.ldap.client")
            -- port 1 has no listener: a connect error here would mean the
            -- client talked to the server before the context step failed
            local c = client:new(ADDR, 1)
            local ok, err = c:gssapi_bind("ldap@unknown.invalid")
            assert(ok == false, "must fail, got " .. tostring(ok))
            assert(err:find("gss_init_sec_context failed", 1, true), "err: " .. tostring(err))
            assert(err:find("not found in Kerberos database", 1, true), "err: " .. err)
            assert(c.socket == nil, "no connection was opened")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 4: no credentials is a clean failure
--- main_config eval: $::MainConfig
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ffi = require("ffi")
            pcall(ffi.cdef, "int setenv(const char *, const char *, int);")
            local saved = os.getenv("KRB5CCNAME")
            ffi.C.setenv("KRB5CCNAME", "FILE:/nonexistent/ccache", 1)

            local client = require("resty.ldap.client")
            local c = client:new(ADDR, 1)
            local ok, err = c:gssapi_bind(SERVICE)
            ffi.C.setenv("KRB5CCNAME", saved, 1)

            assert(ok == false, "must fail, got " .. tostring(ok))
            assert(err:find("gss_init_sec_context failed", 1, true), "err: " .. tostring(err))
            assert(c.socket == nil, "no connection was opened")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 5: a ticket for a service the server holds no key for is rejected by the server
--- main_config eval: $::MainConfig
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            -- the KDC issues the ticket, so the failure is the server's
            local client = require("resty.ldap.client")
            local c = client:new(ADDR, PORT)
            local ok, err = c:gssapi_bind("ldap@otherhost")
            assert(ok == false, "must fail, got " .. tostring(ok))
            assert(err:find("GSSAPI bind failed", 1, true), "err: " .. tostring(err))

            -- the server ended the bind; the session is anonymous and usable
            assert(c.socket ~= nil, "connection kept")
            assert(not sees_self(c), "not bound as user01")
            assert(c:gssapi_bind(SERVICE), "a correct bind on the same connection")
            assert(sees_self(c), "bound as user01")
            assert(c:close())
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
