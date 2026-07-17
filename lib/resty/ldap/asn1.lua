local ffi          = require("ffi")
local C            = ffi.C
local ffi_new      = ffi.new
local ffi_string   = ffi.string
local ffi_cast     = ffi.cast
local band         = require("bit").band
local string_char  = string.char
local string_sub   = string.sub
local table_insert = table.insert
local new_tab      = require("resty.core.base").new_tab

local ucharpp      = ffi_new("unsigned char*[1]")
local charpp       = ffi_new("char*[1]")
local cucharpp     = ffi_new("const unsigned char*[1]")


ffi.cdef [[
    typedef struct asn1_string_st ASN1_OCTET_STRING;
    typedef struct asn1_string_st ASN1_INTEGER;
    typedef struct asn1_string_st ASN1_ENUMERATED;
    typedef struct asn1_string_st ASN1_STRING;

    ASN1_OCTET_STRING *ASN1_OCTET_STRING_new();
    ASN1_INTEGER *ASN1_INTEGER_new();
    ASN1_ENUMERATED *ASN1_ENUMERATED_new();

    void ASN1_INTEGER_free(ASN1_INTEGER *a);
    void ASN1_STRING_free(ASN1_STRING *a);

    long ASN1_INTEGER_get(const ASN1_INTEGER *a);
    long ASN1_ENUMERATED_get(const ASN1_ENUMERATED *a);

    int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
    int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
    int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);

    const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);
    // openssl 1.1.0
    unsigned char *ASN1_STRING_data(ASN1_STRING *x);

    ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a, const unsigned char **ppin, long length);
    ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **ppin, long length);
    ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const unsigned char **ppin, long length);

    int i2d_ASN1_OCTET_STRING(const ASN1_OCTET_STRING *a, unsigned char **pp);
    int i2d_ASN1_INTEGER(const ASN1_INTEGER *a, unsigned char **pp);
    int i2d_ASN1_ENUMERATED(const ASN1_ENUMERATED *a, unsigned char **pp);

    int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
                        int *pclass, long omax);
    int ASN1_object_size(int constructed, int length, int tag);

    void ASN1_put_object(unsigned char **pp, int constructed, int length,
                        int tag, int xclass);
]]


local _M = new_tab(0, 7)


local CLASS = {
    UNIVERSAL = 0x00,
    APPLICATION = 0x40,
    CONTEXT_SPECIFIC = 0x80,
    PRIVATE = 0xc0
}
_M.CLASS = CLASS


local TAG = {
    -- ASN.1 tag values
    EOC = 0,
    BOOLEAN = 1,
    INTEGER = 2,
    OCTET_STRING = 4,
    NULL = 5,
    ENUMERATED = 10,
    SEQUENCE = 16,
    SET = 17,
}
_M.TAG = TAG


local function asn1_put_object(tag, class, constructed, data, len)
    len = type(data) == "string" and #data or len or 0
    if len < 0 then
        return nil, "invalid object length"
    end

    local outbuf = ffi_new("unsigned char[?]", len)
    ucharpp[0] = outbuf

    C.ASN1_put_object(ucharpp, constructed, len, tag, class)
    if not data then
        return ffi_string(outbuf)
    end
    return ffi_string(outbuf) .. data
end

_M.put_object = asn1_put_object


local encode
do
    local encoder = new_tab(0, 3)

    -- Integer
    encoder[TAG.INTEGER] = function(val)
        local typ = C.ASN1_INTEGER_new()
        C.ASN1_INTEGER_set(typ, val)
        charpp[0] = nil
        local ret = C.i2d_ASN1_INTEGER(typ, charpp)
        C.ASN1_INTEGER_free(typ)
        return ffi_string(charpp[0], ret)
    end

    -- Octet String
    encoder[TAG.OCTET_STRING] = function(val)
        local typ = C.ASN1_OCTET_STRING_new()
        C.ASN1_STRING_set(typ, val, #val)
        charpp[0] = nil
        local ret = C.i2d_ASN1_OCTET_STRING(typ, charpp)
        C.ASN1_STRING_free(typ)
        return ffi_string(charpp[0], ret)
    end

    encoder[TAG.ENUMERATED] = function(val)
        local typ = C.ASN1_ENUMERATED_new()
        C.ASN1_ENUMERATED_set(typ, val)
        charpp[0] = nil
        local ret = C.i2d_ASN1_ENUMERATED(typ, charpp)
        C.ASN1_INTEGER_free(typ)
        return ffi_string(charpp[0], ret)
    end

    encoder[TAG.SEQUENCE] = function(val)
        return asn1_put_object(TAG.SEQUENCE, CLASS.UNIVERSAL, 1, val)
    end

    encoder[TAG.SET] = function(val)
        return asn1_put_object(TAG.SET, CLASS.UNIVERSAL, 1, val)
    end

    encoder[TAG.BOOLEAN] = function(val)
        -- tag(BOOLEAN), length(1), value(TRUE: 0xFF, FALSE: 0)
        return string_char(1, 1, val and 0xff or 0)
    end

    function encode(val, tag)
        if tag == nil then
            local typ = type(val)
            if typ == "string" then
                tag = TAG.OCTET_STRING
            elseif typ == "number" then
                tag = TAG.INTEGER
            elseif typ == "boolean" then
                tag = TAG.BOOLEAN
            end
        end

        if encoder[tag] then
            return encoder[tag](val)
        end
    end
end
_M.encode = encode


local MAX_DECODE_DEPTH = 100

local asn1_get_object
do
    local lenp   = ffi_new("long[1]")
    local tagp   = ffi_new("int[1]")
    local classp = ffi_new("int[1]")
    local strpp  = ffi_new("const unsigned char*[1]")

    function asn1_get_object(der, start, stop)
        start = start or 0
        stop = stop or #der
        if stop <= start or stop > #der then
            return nil, "invalid offset"
        end

        local s_der = ffi_cast("const unsigned char *", der)
        strpp[0] = s_der + start

        local ret = C.ASN1_get_object(strpp, lenp, tagp, classp, stop - start)
        -- The 0x80 bit signals an encoding error (also set for the illegal
        -- indefinite/too-long forms). Reject rather than trust the result.
        if band(ret, 0x80) == 0x80 or band(ret, 0x01) == 0x01 then
            return nil, "invalid BER: bad tag/length encoding"
        end

        local content_off = strpp[0] - s_der
        return {
            tag    = tagp[0],
            class  = classp[0],
            len    = tonumber(lenp[0]),
            offset = content_off,           -- 0-indexed content start
            hl     = content_off - start,   -- header length (fixes the hardcoded +2)
            cons   = band(ret, 0x20) == 0x20,
        }
    end
end
_M.get_object = asn1_get_object


local decode
do
    local decoder = new_tab(0, 5)

    -- OCTET STRING: slice raw content bytes directly. Binary/NUL-safe by
    -- construction (no strlen-based ffi_string, no d2i).
    decoder[TAG.OCTET_STRING] = function(der, _, obj)
        return string_sub(der, obj.offset + 1, obj.offset + obj.len)
    end

    -- INTEGER / ENUMERATED: d2i parses a full TLV, so `offset` is the TLV start.
    decoder[TAG.INTEGER] = function(der, offset, obj)
        cucharpp[0] = ffi_cast("const unsigned char *", der) + offset
        local typ = C.d2i_ASN1_INTEGER(nil, cucharpp, obj.hl + obj.len)
        if typ == nil then
            return nil, "invalid INTEGER encoding"
        end
        local v = C.ASN1_INTEGER_get(typ)
        C.ASN1_INTEGER_free(typ)
        return tonumber(v)
    end

    decoder[TAG.ENUMERATED] = function(der, offset, obj)
        cucharpp[0] = ffi_cast("const unsigned char *", der) + offset
        local typ = C.d2i_ASN1_ENUMERATED(nil, cucharpp, obj.hl + obj.len)
        if typ == nil then
            return nil, "invalid ENUMERATED encoding"
        end
        local v = C.ASN1_ENUMERATED_get(typ)
        C.ASN1_INTEGER_free(typ)   -- shares the ASN1_STRING struct; INTEGER_free is correct
        return tonumber(v)
    end

    local function decode_children(der, _, obj, depth)
        local stop = obj.offset + obj.len
        local pos = obj.offset
        local values = {}
        while pos < stop do
            local value, err
            pos, value, err = decode(der, pos, depth + 1)
            if err then
                return nil, err
            end
            table_insert(values, value)
        end
        return values
    end

    decoder[TAG.SEQUENCE] = decode_children
    decoder[TAG.SET]      = decode_children

    -- offset is 0-indexed. Returns next_offset, value, err.
    function decode(der, offset, depth)
        offset = offset or 0
        depth = depth or 0
        if depth > MAX_DECODE_DEPTH then
            return nil, nil, "max decode depth exceeded"
        end
        local obj, err = asn1_get_object(der, offset)
        if not obj then
            return nil, nil, err
        end
        local d = decoder[obj.tag]
        local value, derr
        if d then
            value, derr = d(der, offset, obj, depth)
            if derr then
                return nil, nil, derr
            end
        end
        return obj.offset + obj.len, value
    end
end
_M.decode = decode


return _M
