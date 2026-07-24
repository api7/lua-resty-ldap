-- Reach module-private locals from tests: read (get) or replace (set) a
-- function's named upvalue via the debug library.
local function find(fn, name)
    local i = 1
    while true do
        local n, v = debug.getupvalue(fn, i)
        if not n then return nil end
        if n == name then return i, v end
        i = i + 1
    end
end

local _M = {}

function _M.get(fn, name)
    local _, v = find(fn, name)
    return v
end

function _M.set(fn, name, value)
    local i = find(fn, name)
    if not i then
        return nil, "upvalue not found: " .. name
    end
    debug.setupvalue(fn, i, value)
    return true
end

return _M
