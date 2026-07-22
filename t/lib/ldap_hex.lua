-- Decode a whitespace-tolerant hex string into raw bytes, e.g.
-- h("30 0c 02 01 01") -> "\48\12\2\1\1". Whitespace is stripped first.
return function(s)
    return (s:gsub("%s+", ""):gsub("%x%x", function(b)
        return string.char(tonumber(b, 16))
    end))
end
