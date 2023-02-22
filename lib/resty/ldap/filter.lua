local lpeg = require("lpeg")
local P, R, S, V = lpeg.P, lpeg.R, lpeg.S, lpeg.V
local C, Ct, Cmt, Cg, Cp, Cc, Cf = lpeg.C, lpeg.Ct, lpeg.Cmt, lpeg.Cg, lpeg.Cp, lpeg.Cc, lpeg.Cf

local string_char  = string.char
local string_sub   = string.sub
local table_insert = table.insert
local table_concat = table.concat

local _M = {}

-- Const
_M.OP_TYPE_AND         = 'and'
_M.OP_TYPE_OR          = 'or'
_M.OP_TYPE_NOT         = 'not'
_M.ITEM_TYPE_SUBSTRING = 'substring'
_M.ITEM_TYPE_SIMPLE    = 'simple'
_M.ITEM_TYPE_PRESENT   = 'present'
_M.FILTER_TYPE_EQUAL   = 'equal'
_M.FILTER_TYPE_APPROX  = 'approx'
_M.FILTER_TYPE_GREATER = 'greater'
_M.FILTER_TYPE_LESS    = 'less'


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

-- Grammar
local filter = P{
    'FILTER',
    FILTER = V'FILL' * P'(' * V'OP' * P')' * V'FILL' / function(f)
        return f
    end,

    OP = (V'OP_AND' + V'OP_OR' + V'OP_NOT' + V'ITEM'),
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

    ATTRIBUTE_DESCRIPTION = V'RAW_VALUE' / function(value)
        return { attribute_description = value }
    end,
    ATTRIBUTE_VALUE = V'RAW_VALUE' / function(value)
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
            if v.attribute_value and v.attribute_value ~= "" then
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

    RAW_VALUE = list(V'ESCAPED_CHARACTER' + V'UTF8_FILTERED_CHARACTER') / table_concat, -- UTF8 sequence
    DIGIT = R'09',
    WILDCARD = P'*' / function()
        return { attribute_value = "*" }
    end,
    ESCAPED_CHARACTER = P'\\' * V'ASCII_VALUE',
    ASCII_VALUE = V'HEX_CHAR' * V'HEX_CHAR' / function(value)
        return string_char(tonumber(value, 16))
    end,
    HEX_CHAR = R('af', 'AF', '09'),
    FILL = list(V'SPACE' + V'TAB' + V'SEP', 0) / function() end,
    SPACE = P(string_char(0x20)),         -- ASCII control character - Space
    TAB = P(string_char(0x09)),           -- ASCII control character - TAB
    SEP= (V'CR' * V'LF') + V'CR' + V'LF', -- ASCII control character - CR/LF/CRLF
    CR = P'\r',                           -- ASCII control character - CR
    LF = P'\n',                           -- ASCII control character - LF

    UTF8_CONT = R'\128\191', -- continuation byte
    UTF8_FILTERED_CHARACTER =
        -- Handle some cases where exclusion symbols are not need.
        -- If attribute and value contain struck-out characters, but they are not part of any
        -- operator, capture and skip it without enabling subsequent HEX-based matches
        -- (since these characters are part of value, but HEX matches will unconditionally
        -- strike them out)
        Cmt(R('\0\127'), function(s, i, prev) -- match all ASCII character
            -- Make sure that this character is not the last character, only then it is
            -- possible to compose the operator.
            if #s <= i + 1 then 
                return false
            end

            -- Ensures that the value is parsed properly if there is a separate ~ symbol in the value.
            if string_sub(s, i, i) == '~' and string_sub(s, i + 1, i + 1) ~= "=" then
                -- Captures and skips that ~ symbol. The previous capture element needs to be 
                -- added back manually.
                return i + 1, prev .. '~'
            end

            return false -- No capture by default
        end)
        + R("\0\39", "\43\59", "\63\125", "\127\127") / "%0" -- 1-byte character, remove (, ), <, >, *, =, ~
        + R("\194\223") * V'UTF8_CONT' / "%0" -- 2-byte character
        + R("\224\239") * V'UTF8_CONT' * V'UTF8_CONT' / "%0" -- 3-byte character
        + R("\240\244") * V'UTF8_CONT' * V'UTF8_CONT' * V'UTF8_CONT' / "%0", -- 4-byte character
}


function _M.compile(str)
    local result = filter:match(str)
    if result then
        return result
    end
    return nil, 'syntax error'
end


return _M
