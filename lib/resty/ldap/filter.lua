local lpeg = require('lpeg')
local P, R, S, V = lpeg.P, lpeg.R, lpeg.S, lpeg.V
local C, Ct, Cmt, Cg, Cc, Cf, Cmt = lpeg.C, lpeg.Ct, lpeg.Cmt, lpeg.Cg, lpeg.Cc, lpeg.Cf, lpeg.Cmt
local locale = lpeg.locale()

local next = next
local string_char = string.char
local table_insert = table.insert

local _M = {}

-- Const
_M.OP_TYPE_AND = 'and'
_M.OP_TYPE_OR = 'or'
_M.OP_TYPE_NOT = 'not'
_M.ITEM_TYPE_SUBSTRING = 'substring'
_M.ITEM_TYPE_SIMPLE = 'simple'
_M.ITEM_TYPE_PRESENT = 'present'
_M.FILTER_TYPE_EQUAL = 'equal'
_M.FILTER_TYPE_APPROX = 'approx'
_M.FILTER_TYPE_GREATER = 'greater'
_M.FILTER_TYPE_LESS = 'less'


local function pack(...)
    return { n = select('#', ...), ... }
end

-- Utility
local _= V

local function maybe(pattern)
    if type(pattern) == 'string' then pattern = V(pattern) end
    return pattern ^ -1
end

local function list(pattern, min)
    if type(pattern) == 'string' then pattern = V(pattern) end
    return Ct((pattern) ^ (min or 0))
end

-- Formatters
local cOPBody = function (op_type, ...)
    return {
        op_type = op_type,
        items = (...)[1] ~= nil and (...) or {...}
    }
end

local cItemBody = function (item_type, ...)
    local args = pack(...)
    return {
        item_type = item_type,
        attribute_description = args[1].attribute_description,
        filter_type = args[2].filter_type,
        attribute_value = args[3].attribute_value,
    }
end

-- Simple types
local rawValue = (P'_' + R('az', 'AZ')) * (P'_' + R '09' + R('az', 'AZ')) ^ 0

-- Grammar
local filter = P{
    _'FILTER' / function (f)
        return f
    end,
    FILTER = _'FILL' * P'(' * _'OP' * P')' * _'FILL' / function(f)
        return f
    end,

    OP= (_'OP_AND' + _'OP_OR' + _'OP_NOT' + _'ITEM'),
    OP_AND = (P'&' * _'FILL' * list('FILTER', 1) * _'FILL') / function(...)
        return cOPBody(_M.OP_TYPE_AND, ...)
    end,
    OP_OR = (P'|' * _'FILL' * list('FILTER', 1) * _'FILL') / function(...)
        return cOPBody(_M.OP_TYPE_OR, ...)
    end,
    OP_NOT = 
        (P'!' * (
            (_'FILL' * _'FILTER' * _'FILL') +
            (_'FILL' * _'ITEM' * _'FILL')
        )) / function(...)
            return cOPBody(_M.OP_TYPE_NOT, ...)
        end,
    ITEM = _'ITEM_SUBSTRING' +  _'ITEM_SIMPLE' + _'ITEM_PRESENT',
    ITEM_SUBSTRING = (_'ATTRIBUTE_DESCRIPTION' * _'FILTER_TYPE_EQUAL' * _'ATTRIBUTE_VALUE_SUBSTRING') / function(...)
        return cItemBody(_M.ITEM_TYPE_SUBSTRING, ...)
    end,
    ITEM_SIMPLE = _'ATTRIBUTE_DESCRIPTION' * _'FILTER_TYPE' * _'ATTRIBUTE_VALUE' / function(...)
        return cItemBody(_M.ITEM_TYPE_SIMPLE, ...)
    end,
    ITEM_PRESENT = _'ATTRIBUTE_DESCRIPTION' * P'=*' / function (value)
        return cItemBody(
            _M.ITEM_TYPE_PRESENT, value,
            { filter_type = _M.FILTER_TYPE_EQUAL },
            { attribute_value = "*" }
        )
    end,
    FILTER_TYPE = _'FILTER_TYPE_EQUAL' + _'FILTER_TYPE_APPROX' + _'FILTER_TYPE_GREATER' + _'FILTER_TYPE_LESS',
    FILTER_TYPE_EQUAL = P'=' / function()
        return { filter_type = _M.FILTER_TYPE_EQUAL }
    end,
    FILTER_TYPE_APPROX = P'~=' / function()
        return { filter_type = _M.FILTER_TYPE_APPROX }
    end,
    FILTER_TYPE_GREATER = P'>=' / function()
        return { filter_type = _M.FILTER_TYPE_GREATER }
    end,
    FILTER_TYPE_LESS = P'<=' / function()
        return { filter_type = _M.FILTER_TYPE_LESS }
    end,

    ATTRIBUTE_DESCRIPTION = rawValue / function(value)
        return { attribute_description = value }
    end,
    ATTRIBUTE_VALUE = rawValue / function(value)
        return { attribute_value = value }
    end,
    ATTRIBUTE_VALUE_SUBSTRING =
        ((_'ATTRIBUTE_VALUE' * _'WILDCARD') +
        (_'WILDCARD' * _'ATTRIBUTE_VALUE' * _'WILDCARD') +
        (_'WILDCARD' * _'ATTRIBUTE_VALUE')) / function(...)
            local args = pack(...)
            local s = ''
            for i = 1, args.n, 1 do
                local value = args[i]
                if type(value) == "table" then
                    s = s .. value.attribute_value
                else
                    s = s .. value
                end
            end
            return { attribute_value = s }
        end,

    WILDCARD = P'*' / '*',
    FILL = list(_'SPACE' + _'TAB' + _'SEP', 0) / function() end,
    SPACE = P(string_char(0x20)),
    TAB = P(string_char(0x09)),
    SEP= (_'CR' * _'LF') + _'CR' + _'LF',
    CR = P'\r',
    LF = P'\n',
}


function _M.compile(str)
    local result = filter:match(str)
    if result then
        return result
    end
    return nil, 'syntax error'
end


return _M
