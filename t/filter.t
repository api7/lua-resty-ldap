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

=== TEST 1: basic
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson")
            local filter = require("resty.ldap.filter")

            local cases = {
                {
                    filter = '(objectClass=*)',
                    test = (function(f, m)
                        -- {"item_type":"present","attribute_description":"objectClass","filter_type":"equal","attribute_value":"*"}
                        assert(type(f) == 'table', m .. 'type != table, ' .. type(f))
                        assert(f.item_type == 'present', m .. 'item_type != present, ' .. f.item_type)
                        assert(f.attribute_description == 'objectClass', m .. 'attribute_description != objectClass, ' .. f.attribute_description)
                        assert(f.filter_type == 'equal', m .. 'filter_type != equal, ' .. f.filter_type)
                        assert(f.attribute_value == '*', m .. 'attribute_value != *, '.. f.attribute_value)
                    end),
                },
                {
                    filter = '(objectClass=posixAccount)',
                    test = (function(f, m)
                        -- {"attribute_description":"objectClass","item_type":"simple","attribute_value":"posixAccount","filter_type":"equal"}
                        assert(f.item_type == 'simple', m .. 'item_type != simple, ' .. f.item_type)
                        assert(f.attribute_value == 'posixAccount', m .. 'attribute_value != posixAccount, ' .. f.attribute_value)
                    end)
                },
                {
                    filter = '(objectClass=posix*)',
                    test = (function(f, m)
                        -- {"item_type":"substring","attribute_value":"posix*","filter_type":"equal","attribute_description":"objectClass"}
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(f.attribute_value == 'posix*', m .. 'attribute_value != posix*, ' .. f.attribute_value)
                    end)
                },
                {
                    filter = '(objectClass=*posix*)',
                    test = (function(f, m)
                        -- {"item_type":"substring","attribute_value":"*posix*","filter_type":"equal","attribute_description":"objectClass"}
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(f.attribute_value == '*posix*', m .. 'attribute_value != *posix*, ' .. f.attribute_value)
                    end)
                },
                {
                    filter = '(objectClass=*posix)',
                    test = (function(f, m)
                        -- {"item_type":"substring","attribute_value":"*posix","filter_type":"equal","attribute_description":"objectClass"}
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(f.attribute_value == '*posix', m .. 'attribute_value != *posix, ' .. f.attribute_value)
                    end)
                },
                {
                    filter = '(objectClass~=posix)',
                    test = (function(f, m)
                        -- {"filter_type":"approx","attribute_description":"objectClass","item_type":"simple","attribute_value":"posix"}
                        assert(f.filter_type == 'approx', m .. 'filter_type != substring, ' .. f.filter_type)
                        assert(f.attribute_value == 'posix', m .. 'attribute_value != posix, ' .. f.attribute_value)
                    end)
                },
                {
                    filter = '(test>=posix)',
                    test = (function(f, m)
                        -- {"attribute_value":"posix","filter_type":"greater","attribute_description":"test","item_type":"simple"}
                        assert(f.filter_type == 'greater', m .. 'filter_type != greater, ' .. f.filter_type)
                    end)
                },
                {
                    filter = '(test<=posix)',
                    test = (function(f, m)
                        -- {"attribute_value":"posix","filter_type":"less","attribute_description":"test","item_type":"simple"}
                        assert(f.filter_type == 'less', m .. 'filter_type != less, ' .. f.filter_type)
                    end)
                },
            }

            for i, case in ipairs(cases) do
                local result, err = filter.compile(case.filter)
                if not result then
                    assert(false, 'case#' .. i .. ' compile error: ' .. err)
                end
                ngx.log(ngx.WARN, cjson.encode(result))
                case.test(result, 'case#' .. i .. ' error: ')
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200



=== TEST 2: operation
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson")
            local filter = require("resty.ldap.filter")

            local cases = {
                {
                    filter = '(!objectClass=posixAccount)',
                    test = (function(f, m)
                        -- {"op_type":"not","items":[{"attribute_value":"posixAccount","item_type":"simple","attribute_description":"objectClass","filter_type":"equal"}]}
                        assert(f.op_type and f.op_type == 'not', m .. 'op_type != not, ' .. f.op_type)
                        assert(f.items and next(f.items) ~= nil, m .. 'items not exist or empty, ' .. cjson.encode(f.items))
                        assert(f.items[1] ~= nil, m .. 'items not a object table')
                        assert(f.items[1].attribute_value == 'posixAccount', m .. 'items[1].attribute_value != posixAccount, ' .. f.items[1].attribute_value)
                    end)
                },
                {
                    filter = '(!(objectClass=posixAccount))',
                    test = (function(f, m)
                        -- {"op_type":"not","items":[{"attribute_value":"posixAccount","item_type":"simple","attribute_description":"objectClass","filter_type":"equal"}]}
                        assert(f.op_type and f.op_type == 'not', m .. 'op_type != not, ' .. f.op_type)
                        assert(f.items and next(f.items) ~= nil, m .. 'items not exist or empty, ' .. cjson.encode(f.items))
                        assert(f.items[1] ~= nil, m .. 'items not a object table')
                    end)
                },
                {
                    filter = '(&(objectClass=posixAccount)(cn=user01*))',
                    test = (function(f, m)
                        -- {"items":[{"attribute_value":"posixAccount","attribute_description":"objectClass","filter_type":"equal","item_type":"simple"},{"attribute_value":"user01*","attribute_description":"cn","filter_type":"equal","item_type":"substring"}],"op_type":"and"}
                        assert(f.op_type and f.op_type == 'and', m .. 'op_type != and, ' .. f.op_type)
                        assert(f.items and next(f.items) ~= nil, m .. 'items not exist or empty, ' .. cjson.encode(f.items))
                        assert(f.items[2] ~= nil and f.items[3] == nil, m .. 'items not a object table')
                        assert(f.items[1].item_type == 'simple', m .. 'items[1].item_type != simple, ' .. f.items[1].item_type)
                        assert(f.items[2].item_type == 'substring', m .. 'items[1].item_type != substring, ' .. f.items[1].item_type)
                    end)
                },
                {
                    filter = '(|(&(objectClass=posixAccount)(cn=user01*)(uid=*))(&(objectClass=posixGroup)(uid~=user01)))',
                    test = (function(f, m)
                        -- {"op_type":"or","items":[{"op_type":"and","items":[{"attribute_value":"posixAccount","attribute_description":"objectClass","filter_type":"equal","item_type":"simple"},{"attribute_value":"user01*","attribute_description":"cn","filter_type":"equal","item_type":"substring"},{"attribute_value":"*","attribute_description":"uid","filter_type":"equal","item_type":"present"}]},{"op_type":"and","items":[{"attribute_value":"posixGroup","attribute_description":"objectClass","filter_type":"equal","item_type":"simple"},{"attribute_value":"user01","attribute_description":"uid","filter_type":"approx","item_type":"simple"}]}]}
                        assert(f.op_type and f.op_type == 'or', m .. 'op_type != or, ' .. f.op_type)
                        assert(f.items and next(f.items) ~= nil, m .. 'items not exist or empty, ' .. cjson.encode(f.items))
                        assert(f.items[2] ~= nil and f.items[3] == nil, m .. 'items not a object table')
                        assert(f.items[1].op_type and f.items[1].op_type == 'and', m .. 'items[1].item_type != and, ' .. f.items[1].op_type)
                        assert(f.items[1].op_type and f.items[2].op_type == 'and', m .. 'items[2].item_type != and, ' .. f.items[2].op_type)
                        assert(f.items[1].items[2].item_type == 'substring', m .. 'items[1].items[2].item_type != substring, ' .. f.items[1].items[2].item_type)
                        assert(f.items[1].items[3].item_type == 'present', m .. 'items[1].items[3].item_type != present, ' .. f.items[1].items[3].item_type)
                        assert(f.items[2].items[2].filter_type == 'approx', m .. 'items[2].items[2].filter_type != approx, ' .. f.items[2].items[2].filter_type)
                    end)
                },
                {
                    filter = [[
                        (&
                            (objectClass=posixAccount)
                            (uid=*)
                            (!cn=user01)
                        )
                    ]],
                    test = (function(f, m)
                        -- {"items":[{"attribute_description":"objectClass","attribute_value":"posixAccount","filter_type":"equal","item_type":"simple"},{"attribute_description":"uid","attribute_value":"*","filter_type":"equal","item_type":"present"},{"items":[{"attribute_description":"cn","attribute_value":"user01","filter_type":"equal","item_type":"simple"}],"op_type":"not"}],"op_type":"and"}
                        assert(f.op_type and f.op_type == 'and', m .. 'op_type != and, ' .. f.op_type)
                        assert(f.items and next(f.items) ~= nil, m .. 'items not exist or empty, ' .. cjson.encode(f.items))
                        assert(f.items[3] ~= nil and f.items[4] == nil, m .. 'items not a object table')
                        assert(f.items[2].item_type and f.items[2].item_type == 'present', m .. 'items[2].item_type != present, ' .. f.items[2].item_type)
                        assert(f.items[3].op_type and f.items[3].op_type == 'not', m .. 'items[3].op_type != not, ' .. f.items[3].op_type)
                    end)
                }
            }

            for i, case in ipairs(cases) do
                local result, err = filter.compile(case.filter)
                if not result then
                    assert(false, 'case#' .. i .. ' compile error: ' .. err)
                end
                ngx.log(ngx.WARN, cjson.encode(result))
                case.test(result, 'case#' .. i .. ' error: ')
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200
