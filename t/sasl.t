use Test::Nginx::Socket::Lua;

log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;t/lib/?.lua;/usr/share/lua/5.1/?.lua;;';
    lua_package_cpath 'deps/lib/lua/5.1/?.so;;';
_EOC_

# A scripted server and GSS-API context for driving client:gssapi_bind()
# without a KDC; the real exchange is covered by t/gssapi.t.
our $MockConfig = $HttpConfig . <<'_EOC_';
    init_by_lua_block {
        local ldap_hex = require("ldap_hex")

        -- BindResponses: resultCode, then serverSaslCreds when given
        R = {
            progress_aabbcc = ldap_hex("30 11 02 01 01 61 0c 0a 01 0e 04 00 04 00 87 03 aa bb cc"),
            progress_ddee   = ldap_hex("30 10 02 01 01 61 0b 0a 01 0e 04 00 04 00 87 02 dd ee"),
            progress_none   = ldap_hex("30 0c 02 01 01 61 07 0a 01 0e 04 00 04 00"),
            success         = ldap_hex("30 0c 02 01 01 61 07 0a 01 00 04 00 04 00"),
            success_aabbcc  = ldap_hex("30 11 02 01 01 61 0c 0a 01 00 04 00 04 00 87 03 aa bb cc"),
            invalid_creds   = ldap_hex("30 0c 02 01 01 61 07 0a 01 31 04 00 04 00"),
            search_done     = ldap_hex("30 0c 02 01 01 65 07 0a 01 00 04 00 04 00"),
        }

        function fake_sock(responses)
            local buf = table.concat(responses)
            local s = { sent = {} }
            function s.send(_, p) s.sent[#s.sent + 1] = p return #p end
            function s.receive(_, n)
                if #buf < n then return nil, "closed" end
                local r = buf:sub(1, n)
                buf = buf:sub(n + 1)
                return r
            end
            function s.close() s.closed = true return true end
            function s.setkeepalive() s.kept = true return true end
            return s
        end

        -- steps: list of { token, complete } or { nil, err } returned in turn
        function fake_gssapi(steps, offer)
            local ctx = { inputs = {}, wrapped = {} }
            local i = 0
            function ctx.step(_, in_token)
                i = i + 1
                ctx.inputs[i] = in_token == nil and "<nil>" or in_token
                local st = assert(steps[i], "unexpected step " .. i)
                return st[1], st[2]
            end
            function ctx.unwrap(_, t)
                ctx.unwrapped = t
                return offer or "\7\0\16\0"
            end
            function ctx.wrap(_, m)
                ctx.wrapped[#ctx.wrapped + 1] = m
                return "W:" .. m
            end
            function ctx.free() ctx.freed = true end
            return { new = function(name) ctx.service = name return ctx end }, ctx
        end

        function mock_client(responses, steps, offer)
            local client = require("resty.ldap.client")
            local upvalue = require("upvalue")
            local mod, ctx = fake_gssapi(steps, offer)
            assert(upvalue.set(client.gssapi_bind, "gssapi", mod))
            local c = client:new("127.0.0.1", 1389)
            local sock = fake_sock(responses)
            c.socket = sock
            return c, sock, ctx
        end
    }
_EOC_

run_tests();

__DATA__

=== TEST 1: sasl_bind_request encodes SaslCredentials
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- BindRequest { version 3, name "", sasl [3] { "GSSAPI", creds } }
            local with = assert(protocol.sasl_bind_request("GSSAPI", "\1\2"))
            assert(with:sub(-21) == ldap_hex(
                "60 13 02 01 03 04 00 a3 0c 04 06 47 53 53 41 50 49 04 02 01 02"),
                "with credentials")

            -- nil omits the credentials field
            local without = assert(protocol.sasl_bind_request("GSSAPI"))
            assert(without:sub(-17) == ldap_hex(
                "60 0f 02 01 03 04 00 a3 08 04 06 47 53 53 41 50 49"),
                "without credentials")

            -- "" is an empty response, which is not the same as none
            local empty = assert(protocol.sasl_bind_request("GSSAPI", ""))
            assert(empty:sub(-19) == ldap_hex(
                "60 11 02 01 03 04 00 a3 0a 04 06 47 53 53 41 50 49 04 00"),
                "empty credentials")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 2: sasl_bind_request rejects invalid arguments
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            for _, m in ipairs({ false, 1, "", {} }) do
                local req, err = protocol.sasl_bind_request(m, "x")
                assert(req == nil and err == "SASL mechanism must be a non-empty string",
                       "mechanism " .. tostring(m))
            end
            for _, c in ipairs({ false, 1, {} }) do
                local req, err = protocol.sasl_bind_request("GSSAPI", c)
                assert(req == nil and err == "SASL credentials must be a string",
                       "credentials " .. tostring(c))
            end
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 3: BindResponse serverSaslCreds is decoded
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            local res = assert(protocol.decode_message(ldap_hex(
                "30 11 02 01 01 61 0c 0a 01 0e 04 00 04 00 87 03 aa bb cc")))
            assert(res.result_code == protocol.RESULT_SASL_BIND_IN_PROGRESS, "code 14")
            assert(res.server_sasl_creds == "\170\187\204", "creds")

            -- after an optional referral [3]
            res = assert(protocol.decode_message(ldap_hex(
                "30 18 02 01 01 61 13 0a 01 0e 04 00 04 00 a3 05 04 03 61 62 63 87 03 aa bb cc")))
            assert(res.server_sasl_creds == "\170\187\204", "creds after referral")

            -- present but empty
            res = assert(protocol.decode_message(ldap_hex(
                "30 0e 02 01 01 61 09 0a 01 0e 04 00 04 00 87 00")))
            assert(res.server_sasl_creds == "", "empty creds")

            -- absent
            res = assert(protocol.decode_message(ldap_hex(
                "30 0c 02 01 01 61 07 0a 01 00 04 00 04 00")))
            assert(res.server_sasl_creds == nil, "no creds")

            -- only a BindResponse carries them
            res = assert(protocol.decode_message(ldap_hex(
                "30 11 02 01 01 65 0c 0a 01 00 04 00 04 00 87 03 aa bb cc")))
            assert(res.server_sasl_creds == nil, "SearchResultDone has no creds")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 4: malformed serverSaslCreds are rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local protocol = require("resty.ldap.protocol")
            local ldap_hex = require("ldap_hex")

            -- constructed [7]
            local res, err = protocol.decode_message(ldap_hex(
                "30 11 02 01 01 61 0c 0a 01 0e 04 00 04 00 a7 03 04 01 aa"))
            assert(res == nil and err, "constructed creds must be rejected")

            -- overruns the BindResponse
            res, err = protocol.decode_message(ldap_hex(
                "30 11 02 01 01 61 0c 0a 01 0e 04 00 04 00 87 04 aa bb cc"))
            assert(res == nil and err, "overrunning creds must be rejected")

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 5: gssapi_bind runs the RFC 4752 exchange
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            local c, sock, ctx = mock_client(
                { R.progress_aabbcc, R.progress_ddee, R.success },
                { { "T1", false }, { "", true } })

            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == true, "bind: " .. tostring(err))
            assert(ctx.service == "ldap@ldap.example.org", "service name")

            -- context tokens: none in, then the server's token
            assert(ctx.inputs[1] == "<nil>", "first step takes no token")
            assert(ctx.inputs[2] == "\170\187\204", "second step gets the server token")

            -- the offer is unwrapped, and "no layer, max size 0" wrapped back
            assert(ctx.unwrapped == "\221\238", "offer unwrapped")
            assert(ctx.wrapped[1] == "\1\0\0\0", "layer choice")

            assert(#sock.sent == 3, "three requests, got " .. #sock.sent)
            assert(sock.sent[1]:sub(-4) == "\4\2T1", "first token sent")
            assert(sock.sent[2]:sub(-2) == "\4\0", "empty response once complete")
            assert(sock.sent[3]:sub(-8) == "\4\6W:\1\0\0\0", "wrapped layer choice sent")

            assert(not sock.closed, "a bound session stays open")
            assert(rawequal(c.socket, sock), "and attached to the client")
            assert(ctx.freed, "context released")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 6: a server-rejected bind is false and keeps the session
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            local c, sock, ctx = mock_client({ R.invalid_creds }, { { "T1", false } })
            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false, "rejected bind is false")
            assert(err:find("GSSAPI bind failed", 1, true), "err: " .. tostring(err))
            assert(err:find("The supplied credential is invalid", 1, true), "err: " .. err)
            -- the server ended the bind, the session is anonymous and usable
            assert(not sock.closed, "socket kept")
            assert(ctx.freed, "context released")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 7: a context failure before any request leaves the session alone
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            local c, sock = mock_client({}, { { nil, "no credentials" } })
            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err == "no credentials", "err: " .. tostring(err))
            assert(#sock.sent == 0, "nothing sent")
            assert(not sock.closed, "socket kept")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 8: a context failure mid-exchange drops the connection
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            local c, sock = mock_client({ R.progress_aabbcc },
                                        { { "T1", false }, { nil, "bad token" } })
            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err == "bad token", "err: " .. tostring(err))
            -- the server is still waiting for the next step
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")
            assert(c.socket == nil, "and detached")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 9: success before the context is established is refused
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            -- the server never proved its identity
            local c, sock = mock_client({ R.success }, { { "T1", false } })
            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false, "must not succeed")
            assert(err:find("succeeded before the security layer negotiation", 1, true),
                   "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 10: success before the security layer negotiation is refused
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            -- RFC 4752 s3.1 requires the layer negotiation even when no layer
            -- is chosen: success once the context is complete is refused...
            local c, sock = mock_client({ R.progress_aabbcc, R.success },
                                        { { "T1", false }, { "", true } })
            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false, "must not succeed")
            assert(err:find("succeeded before the security layer negotiation", 1, true),
                   "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")

            -- ...and so is a final context token piggybacked on success
            local ctx
            c, sock, ctx = mock_client({ R.success_aabbcc },
                                       { { "T1", false }, { "", true } })
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false, "must not succeed")
            assert(err:find("succeeded before the security layer negotiation", 1, true),
                   "err: " .. tostring(err))
            assert(#ctx.inputs == 1, "the piggybacked token is not consumed")
            assert(ctx.unwrapped == nil and #ctx.wrapped == 0, "no layer negotiation")
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 11: the security layer exchange is validated
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            local steps = { { "T1", false }, { "", true } }

            -- no offer at all
            local c, sock = mock_client({ R.progress_aabbcc, R.progress_none }, steps)
            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err:find("did not send a security layer offer", 1, true),
                   "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")

            -- not exactly 4 bytes, too short or too long
            for _, offer in ipairs({ "\1\0", "\1\0\16\0\0" }) do
                c, sock = mock_client({ R.progress_aabbcc, R.progress_ddee }, steps, offer)
                ok, err = c:gssapi_bind("ldap@ldap.example.org")
                assert(ok == false and err:find("exactly 4 bytes", 1, true),
                       "err: " .. tostring(err))
                assert(sock.closed, "socket closed")
                assert(c.socket == nil, "socket detached, so it cannot be pooled")
            end

            -- integrity/privacy only: no-security-layer bit clear
            c, sock = mock_client({ R.progress_aabbcc, R.progress_ddee }, steps, "\6\0\16\0")
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err:find("requires a security layer", 1, true),
                   "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")

            -- no layer at all on offer, yet a nonzero maximum buffer
            c, sock = mock_client({ R.progress_aabbcc, R.progress_ddee }, steps, "\1\0\16\0")
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err:find("nonzero maximum buffer size", 1, true),
                   "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")

            -- which is fine with a zero one
            c, sock = mock_client({ R.progress_aabbcc, R.progress_ddee, R.success }, steps,
                                  "\1\0\0\0")
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == true, "no-layer-only offer: " .. tostring(err))

            -- a rejected layer choice ends the bind: the session is kept
            c, sock = mock_client({ R.progress_aabbcc, R.progress_ddee, R.invalid_creds }, steps)
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err:find("security layer negotiation failed", 1, true),
                   "err: " .. tostring(err))
            assert(not sock.closed, "socket kept")

            -- but a server asking for more after the layer choice leaves the
            -- bind open on its side
            c, sock = mock_client({ R.progress_aabbcc, R.progress_ddee, R.progress_none }, steps)
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err:find("did not end after the security layer choice", 1, true),
                   "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 12: transport and protocol failures
--- http_config eval: $::MockConfig
--- config
    location /t {
        content_by_lua_block {
            -- connection drops before the response: nil, like simple_bind
            local c, sock = mock_client({}, { { "T1", false } })
            local ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == nil, "transport failure is nil, got " .. tostring(ok))
            assert(err:find("receive response failed", 1, true), "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")

            -- a response that is not a BindResponse
            c, sock = mock_client({ R.search_done }, { { "T1", false } })
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err:find("incorrect Op", 1, true), "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")

            -- a server that never stops asking for more
            local steps, resp = {}, {}
            for i = 1, 20 do
                steps[i] = { "T", false }
                resp[i] = R.progress_aabbcc
            end
            c, sock = mock_client(resp, steps)
            ok, err = c:gssapi_bind("ldap@ldap.example.org")
            assert(ok == false and err == "GSSAPI bind did not converge", "err: " .. tostring(err))
            assert(sock.closed, "socket closed")
            assert(c.socket == nil, "socket detached, so it cannot be pooled")
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 13: gssapi.new rejects an invalid service name
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local gssapi = require("resty.ldap.gssapi")
            for _, n in ipairs({ false, 1, "" }) do
                local ctx, err = gssapi.new(n)
                assert(ctx == nil and err == "service name must be a non-empty string",
                       tostring(n))
            end
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
