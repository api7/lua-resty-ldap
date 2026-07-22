-- Decode a whitespace-tolerant hex string into raw bytes, e.g.
-- h("30 0c 02 01 01") -> "\48\12\2\1\1". Whitespace is stripped first.
return function(s)
    local hex = s:gsub("%s+", "")
    if hex:find("%X") then
        error("ldap_hex: non-hex character in input", 2)
    end
    if #hex % 2 ~= 0 then
        error("ldap_hex: odd number of hex digits", 2)
    end
    return (hex:gsub("%x%x", function(b)
        return string.char(tonumber(b, 16))
    end))
end
