use Test::Nginx::Socket::Lua;

log_level('info');
no_shuffle();
no_long_string();
repeat_each(1);
plan 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path 'deps/share/lua/5.1/?.lua;/usr/share/lua/5.1/?.lua;;';
    lua_package_cpath 'deps/?.so;;';
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
                        assert(f.item_type == 'simple', m .. 'item_type != simple, ' .. f.item_type)
                        assert(f.attribute_value == 'posixAccount', m .. 'attribute_value != posixAccount, ' .. f.attribute_value)
                    end)
                },
                {
                    filter = '(objectClass=posix*)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == 'posix', m .. 'attribute_value[1] != posix, ' .. f.attribute_value[1])
                        assert(f.attribute_value[2] == '*', m .. 'attribute_value[2] != *, ' .. f.attribute_value[2])
                    end)
                },
                {
                    filter = '(objectClass=*posix*)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == '*', m .. 'attribute_value[1] != *, ' .. f.attribute_value[1])
                        assert(f.attribute_value[2] == 'posix', m .. 'attribute_value[2] != posix, ' .. f.attribute_value[2])
                        assert(f.attribute_value[3] == '*', m .. 'attribute_value[3] != *, ' .. f.attribute_value[3])
                    end)
                },
                {
                    filter = '(objectClass=*posix)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == '*', m .. 'attribute_value[1] != *, ' .. f.attribute_value[1])
                        assert(f.attribute_value[2] == 'posix', m .. 'attribute_value[2] != posix, ' .. f.attribute_value[2])
                    end)
                },
                {
                    filter = '(objectClass~=posix)',
                    test = (function(f, m)
                        assert(f.filter_type == 'approx', m .. 'filter_type != approx, ' .. f.filter_type)
                        assert(f.attribute_value == 'posix', m .. 'attribute_value != posix, ' .. f.attribute_value)
                    end)
                },
                {
                    filter = '(test>=posix)',
                    test = (function(f, m)
                        assert(f.filter_type == 'greater', m .. 'filter_type != greater, ' .. f.filter_type)
                    end)
                },
                {
                    filter = '(test<=posix)',
                    test = (function(f, m)
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
                            (!(cn=user01))
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



=== TEST 3: substring
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson")
            local filter = require("resty.ldap.filter")

            local cases = {
                {
                    filter = '(objectClass=abcabc*)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == 'abcabc', m .. 'attribute_value[1] != abcabc, ' .. f.attribute_value[1])
                        assert(f.attribute_value[2] == '*', m .. 'attribute_value[2] != *, ' .. f.attribute_value[2])
                    end),
                },
                {
                    filter = '(objectClass=*abcabc)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == '*', m .. 'attribute_value[1] != *, ' .. f.attribute_value[1])
                        assert(f.attribute_value[2] == 'abcabc', m .. 'attribute_value[2] != abcabc, ' .. f.attribute_value[2])
                    end),
                },
                {
                    filter = '(objectClass=*abcabc*)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == '*', m .. 'attribute_value[1] != *, ' .. f.attribute_value[1])
                        assert(f.attribute_value[2] == 'abcabc', m .. 'attribute_value[2] != abcabc, ' .. f.attribute_value[2])
                        assert(f.attribute_value[3] == '*', m .. 'attribute_value[3] != *, ' .. f.attribute_value[3])
                    end),
                },
                {
                    filter = '(objectClass=abcabc1*abcabc2)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == 'abcabc1', m .. 'attribute_value[1] != abcabc1, ' .. f.attribute_value[1])
                        assert(f.attribute_value[2] == '*', m .. 'attribute_value[2] != *, ' .. f.attribute_value[2])
                        assert(f.attribute_value[3] == 'abcabc2', m .. 'attribute_value[3] != abcabc2, ' .. f.attribute_value[3])
                    end),
                },
                {
                    filter = '(objectClass=*abcabc1*abcabc2)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == '*', m .. 'attribute_value[1] != *, ' .. f.attribute_value[1])
                        assert(f.attribute_value[4] == 'abcabc2', m .. 'attribute_value[4] != abcabc2, ' .. f.attribute_value[4])
                    end),
                },
                {
                    filter = '(objectClass=*abcabc1*abcabc2*)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == '*', m .. 'attribute_value[1] != *, ' .. f.attribute_value[1])
                        assert(f.attribute_value[4] == 'abcabc2', m .. 'attribute_value[4] != abcabc2, ' .. f.attribute_value[4])
                        assert(f.attribute_value[5] == '*', m .. 'attribute_value[5] != *, ' .. f.attribute_value[5])
                    end),
                },
                {
                    filter = '(objectClass=abcabc1*abcabc2*abcabc3*abcabc4)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == 'abcabc1', m .. 'attribute_value[1] != abcabc1, ' .. f.attribute_value[1])
                        assert(f.attribute_value[4] == '*', m .. 'attribute_value[4] != *, ' .. f.attribute_value[4])
                        assert(f.attribute_value[5] == 'abcabc3', m .. 'attribute_value[5] != abcabc3, ' .. f.attribute_value[5])
                    end),
                },
                {
                    filter = '(objectClass=*abcabc1*abcabc2*abcabc3*abcabc4*)',
                    test = (function(f, m)
                        assert(f.item_type == 'substring', m .. 'item_type != substring, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        assert(f.attribute_value[1] == '*', m .. 'attribute_value[1] != *, ' .. f.attribute_value[1])
                        assert(f.attribute_value[4] == 'abcabc2', m .. 'attribute_value[4] != abcabc2, ' .. f.attribute_value[4])
                        assert(f.attribute_value[6] == 'abcabc3', m .. 'attribute_value[6] != abcabc3, ' .. f.attribute_value[6])
                        assert(f.attribute_value[9] == '*', m .. 'attribute_value[9] != *, ' .. f.attribute_value[9])
                    end),
                },
                {
                    filter = '(objectClass=*)',
                    test = (function(f, m)
                        assert(f.item_type == 'present', m .. 'item_type != present, ' .. f.item_type)
                        assert(type(f.attribute_value) == 'string', m .. 'attribute_value not a string, ' .. type(f.attribute_value))
                        assert(f.attribute_value == '*', m .. 'attribute_value != *, ' .. f.attribute_value)
                    end),
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



=== TEST 4: go-ldap cases
Implement the filter compilation test in https://github.com/go-ldap/ldap,
removing the extensible match implementation from it.
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require("cjson")
            local filter = require("resty.ldap.filter")
            local to_hex = require("resty.string").to_hex
            local asn1_encode = require("resty.ldap.asn1").encode

            local cases = {
                {-- #1
                    filter = '(&(sn=Miller)(givenName=Bob))'
                },
                {-- #2
                    filter = '(|(sn=Miller)(givenName=Bob))'
                },
                {-- #3
                    filter = '(sn=Miller)'
                },
                {-- #4
                    filter = '(sn=Mill*)'
                },
                {-- #5
                    filter = '(sn=*Mill)'
                },
                {-- #6
                    filter = '(sn=*Mill*)'
                },
                {-- #7
                    filter = '(sn=*i*le*)'
                },
                {-- #8
                    filter = '(sn=Mi*l*r)'
                },
                {-- #9
                    filter = '(sn=Mi*함*r)',
                    test = (function(f, m)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        local str = table.concat(f.attribute_value)
                        assert(str == 'Mi*함*r', m .. 'attribute_value not equal to Mi*함*r, ' .. str)
                        assert(to_hex(str) == '4d692aed95a82a72', m .. 'attribute_value in hex not equal to 4d692aed95a82a72, ' .. to_hex(str))
                    end),
                },
                {-- #10
                    filter = '(sn=Mi*\\ed\\95\\a8*r)',
                    test = (function(f, m)
                        assert(type(f.attribute_value) == 'table', m .. 'attribute_value not a table, ' .. type(f.attribute_value))
                        local str = table.concat(f.attribute_value)
                        assert(str == 'Mi*함*r', m .. 'attribute_value not equal to Mi*함*r, ' .. str)
                        assert(to_hex(str) == '4d692aed95a82a72', m .. 'attribute_value in hex not equal to 4d692aed95a82a72, ' .. to_hex(str))
                    end),
                },
                {-- #11
                    filter = '(sn=Mi*le*)'
                },
                {-- #12
                    filter = '(sn=*i*ler)'
                },
                {-- #13
                    filter = '(sn>=Miller)'
                },
                {-- #14
                    filter = '(sn<=Miller)'
                },
                {-- #15
                    filter = '(sn=*)'
                },
                {-- #16
                    filter = '(sn~=Miller)'
                },
                {-- #17 27fcfea3abf9904eaa476dd57ed132
                    filter = "(objectGUID='\\fc\\fe\\a3\\ab\\f9\\90N\\aaGm\\d5I~\\d12)",
                    test = (function(f, m)
                        local str = f.attribute_value
                        assert(to_hex(str) == '27fcfea3abf9904eaa476dd5497ed132', m .. 'attribute_value in hex not equal to 27fcfea3abf9904eaa476dd5497ed132, ' .. to_hex(str))
                    end),
                },
                {-- #18
                    filter = '(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)',
                    test = (function(f, m)
                        local target = 'd0b0d0b1d0b2d0b3d0b4d0b5d191d0b6d0b7d0b8d0b9d0bad0bbd0bcd0bdd0bed0bfd180d181d182d183d184d185d186d187d188d189d18ad18bd18cd18dd18ed18f'
                        local str = f.attribute_value
                        assert(str == 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя', m .. 'attribute_value not equal to абвгдеёжзийклмнопрстуфхцчшщъыьэюя, ' .. str)
                        assert(
                            to_hex(str) == target,
                            m .. 'attribute_value in hex not equal to ' .. target .. ', ' .. to_hex(str)
                        )
                    end),
                },
                {-- #19
                    filter = '(objectGUID=함수목록)',
                    test = (function(f, m)
                        local str = f.attribute_value
                        assert(str == '함수목록', m .. 'attribute_value not equal to 함수목록, ' .. str)
                        assert(to_hex(str) == 'ed95a8ec8898ebaaa9eba19d', m .. 'attribute_value in hex not equal to ed95a8ec8898ebaaa9eba19d, ' .. to_hex(str))
                    end),
                },
                {-- #20
                    filter = '(objectGUID=',
                    expect_err = "syntax error",
                },
                {-- #21
                    filter = '(objectGUID=함수목록',
                    expect_err = "syntax error",
                },
                {-- #22
                    filter = '((cn=)',
                    expect_err = "syntax error",
                },
                {-- #23
                    filter = '(&(objectclass=inetorgperson)(cn=中文))',
                    test = (function(f, m)
                        local str = f.items[2].attribute_value
                        assert(f.op_type == 'and', m .. 'op_type not equal to and, ' .. f.op_type)
                        assert(#f.items == 2 and str == '中文', m .. 'items[2].attribute_value not equal to 中文, ' .. str)
                    end),
                },
            }

            for i, case in ipairs(cases) do
                local result, err = filter.compile(case.filter)
                if not result then
                    if case.expect_err then
                        assert(case.expect_err == err, 
                                'case#' .. i .. ' error content does not match expectations, expect: '
                                .. case.expect_err .. ', actual: ' .. err)
                    else
                        assert(false, 'case#' .. i .. ' compile error: ' .. err)
                    end
                end
                ngx.log(ngx.WARN, cjson.encode(result))
                if case.test then
                    case.test(result, 'case#' .. i .. ' error: ')
                end
            end
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_code: 200
