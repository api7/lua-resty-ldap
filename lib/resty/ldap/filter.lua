local lpeg = require('lpeg')
local P, R, S, V = lpeg.P, lpeg.R, lpeg.S, lpeg.V
local C, Ct, Cmt, Cg, Cc, Cf, Cmt = lpeg.C, lpeg.Ct, lpeg.Cmt, lpeg.Cg, lpeg.Cc, lpeg.Cf, lpeg.Cmt

local string_char = string.char
local table_insert = table.insert
local table_concat = table.concat

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
local function maybe(pattern)
    if type(pattern) == 'string' then pattern = V(pattern) end
    return pattern ^ -1
end

local function list(pattern, min)
    if type(pattern) == 'string' then pattern = V(pattern) end
    return Ct((pattern) ^ (min or 0))
end

-- Formatters
local cOPBody = function(op_type, ...)
    return {
        op_type = op_type,
        items = (...)[1] ~= nil and (...) or {...}
    }
end

local cItemBody = function(item_type_hint, ...)
    local args = {...}
    local attribute_value = args[3].attribute_value

    if not item_type_hint then
        if #attribute_value == 1 and attribute_value[1] == "*" then
            item_type_hint = _M.ITEM_TYPE_PRESENT
            attribute_value = attribute_value[1]
        else
            item_type_hint = _M.ITEM_TYPE_SUBSTRING
        end
    end

    return {
        item_type = item_type_hint,
        attribute_description = args[1].attribute_description,
        filter_type = args[2].filter_type,
        attribute_value = attribute_value,
    }
end

-- Simple types
local rawValue = (P'_' + R'09' + R('az', 'AZ')) * (P'_' + R'09' + R('az', 'AZ')) ^ 0

-- Grammar
local filter = P{
    V'FILTER' / function(f)
        return f
    end,
    FILTER = V'FILL' * P'(' * V'OP' * P')' * V'FILL' / function(f)
        return f
    end,

    OP= (V'OP_AND' + V'OP_OR' + V'OP_NOT' + V'ITEM'),
    OP_AND = (P'&' * V'FILL' * list('FILTER', 1) * V'FILL') / function(...)
        return cOPBody(_M.OP_TYPE_AND, ...)
    end,
    OP_OR = (P'|' * V'FILL' * list('FILTER', 1) * V'FILL') / function(...)
        return cOPBody(_M.OP_TYPE_OR, ...)
    end,
    OP_NOT =
        (P'!' * V'FILL' * V'FILTER' * V'FILL') / function(...)
            return cOPBody(_M.OP_TYPE_NOT, ...)
        end,
    ITEM = V'ITEM_PRESENT_AND_SUBSTRING' +  V'ITEM_SIMPLE',
    ITEM_PRESENT_AND_SUBSTRING = (V'ATTRIBUTE_DESCRIPTION' * V'FILTER_TYPE_EQUAL' * V'ATTRIBUTE_VALUE_SUBSTRING') / function(...)
        return cItemBody(nil, ...)
    end,
    ITEM_SIMPLE = V'ATTRIBUTE_DESCRIPTION' * V'FILTER_TYPE' * V'ATTRIBUTE_VALUE' / function(...)
        return cItemBody(_M.ITEM_TYPE_SIMPLE, ...)
    end,
    FILTER_TYPE = V'FILTER_TYPE_EQUAL' + V'FILTER_TYPE_APPROX' + V'FILTER_TYPE_GREATER' + V'FILTER_TYPE_LESS',
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
    ATTRIBUTE_VALUE_SUBSTRING = (
        maybe('ATTRIBUTE_VALUE') *
        V'WILDCARD' *
        list(V'ATTRIBUTE_VALUE' * V'WILDCARD', 0) *
        maybe('ATTRIBUTE_VALUE')
    ) / function(...)
        local s = {}
        for i = 1, select('#', ...) do
            local v = select(i, ...)
            if v.attribute_value then
                table_insert(s, v.attribute_value)
            elseif #v > 0 and v[1] then -- check if the elements are arrays
                -- When there is the following format xxx*a*b*c*xxx,
                -- the parser will output a*b*c* as a nested two-dimensional array,
                -- which we need to flatten
                for _, any_item in ipairs(v) do
                    table_insert(s, any_item.attribute_value)
                end
            end
        end
        return { attribute_value = s }
    end,

    WILDCARD = P'*' / function()
        return { attribute_value = "*" }
    end,
    FILL = list(V'SPACE' + V'TAB' + V'SEP', 0) / function() end,
    SPACE = P(string_char(0x20)),         -- ASCII control charactor - Space
    TAB = P(string_char(0x09)),           -- ASCII control charactor - TAB
    SEP= (V'CR' * V'LF') + V'CR' + V'LF', -- ASCII control charactor - CR/LF/CRLF
    CR = P'\r',                           -- ASCII control charactor - CR
    LF = P'\n',                           -- ASCII control charactor - LF
}


function _M.compile(str)
    local result = filter:match(str)
    if result then
        return result
    end
    return nil, 'syntax error'
end


return _M
