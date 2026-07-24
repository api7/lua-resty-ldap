local ffi           = require("ffi")
local C             = ffi.C
local ffi_new       = ffi.new
local ffi_string    = ffi.string
local ffi_cast      = ffi.cast
local band          = require("bit").band
local string_byte   = string.byte
local string_char   = string.char
local string_format = string.format
local string_sub    = string.sub
local new_tab       = require("resty.core.base").new_tab

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

    // frees the buffer i2d_* allocates when *pp is NULL
    void CRYPTO_free(void *ptr, const char *file, int line);

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


-- ASN1_put_object emits at most 11 header bytes (tag + long-form length)
local hdrbuf = ffi_new("unsigned char[16]")

-- length is a C int; guard against FFI-boundary truncation/clamping
local INT_MAX = 2147483647

local function asn1_put_object(tag, class, constructed, data, len)
    -- a non-string payload would coerce via tostring() with len 0, emitting a
    -- header that disagrees with the bytes that follow it
    if data ~= nil and type(data) ~= "string" then
        return nil, "invalid object payload"
    end
    if data ~= nil then
        len = #data
    elseif len == nil then
        len = 0
    end
    if type(len) ~= "number" or len % 1 ~= 0 or len < 0 or len > INT_MAX then
        return nil, "invalid object length"
    end

    -- read back exactly the header bytes written; a strlen-based read would
    -- truncate a length octet containing 0x00 (e.g. 256 -> 82 01 00)
    ucharpp[0] = hdrbuf
    C.ASN1_put_object(ucharpp, constructed, len, tag, class)
    local header = ffi_string(hdrbuf, ucharpp[0] - hdrbuf)
    if not data then
        return header
    end
    return header .. data
end

_M.put_object = asn1_put_object


-- 2^53: largest magnitude a Lua 5.1 double holds exactly; matches the decoder
local INT_EXACT = 9007199254740992

local encode
do
    local encoder = new_tab(0, 3)

    -- refuse values the C long conversion would truncate/clamp; the integrality
    -- test also rejects NaN and +/-inf ((0/0)%1 and (1/0)%1 are NaN)
    local function integer_encodable(val)
        return type(val) == "number" and val % 1 == 0
               and val <= INT_EXACT and val >= -INT_EXACT
    end

    -- i2d with *pp == NULL allocates a buffer we own; copy it out then free it,
    -- else a worker leaks one encoding per encode. charpp is module-level.
    local function take_i2d_output(ret)
        if ret <= 0 then
            charpp[0] = nil
            return nil, "failed to encode ASN.1 value"
        end
        local out = ffi_string(charpp[0], ret)
        C.CRYPTO_free(charpp[0], "asn1.lua", 0)
        charpp[0] = nil
        return out
    end

    -- Integer
    encoder[TAG.INTEGER] = function(val)
        if not integer_encodable(val) then
            return nil, "INTEGER value is not an exactly representable integer"
        end
        local typ = C.ASN1_INTEGER_new()
        C.ASN1_INTEGER_set(typ, val)
        charpp[0] = nil
        local ret = C.i2d_ASN1_INTEGER(typ, charpp)
        C.ASN1_INTEGER_free(typ)
        return take_i2d_output(ret)
    end

    -- Octet String
    encoder[TAG.OCTET_STRING] = function(val)
        if type(val) ~= "string" then
            return nil, "OCTET STRING value must be a string"
        end
        local typ = C.ASN1_OCTET_STRING_new()
        C.ASN1_STRING_set(typ, val, #val)
        charpp[0] = nil
        local ret = C.i2d_ASN1_OCTET_STRING(typ, charpp)
        C.ASN1_STRING_free(typ)
        return take_i2d_output(ret)
    end

    encoder[TAG.ENUMERATED] = function(val)
        if not integer_encodable(val) then
            return nil, "ENUMERATED value is not an exactly representable integer"
        end
        local typ = C.ASN1_ENUMERATED_new()
        C.ASN1_ENUMERATED_set(typ, val)
        charpp[0] = nil
        local ret = C.i2d_ASN1_ENUMERATED(typ, charpp)
        C.ASN1_INTEGER_free(typ)   -- shares the ASN1_STRING struct
        return take_i2d_output(ret)
    end

    encoder[TAG.SEQUENCE] = function(val)
        return asn1_put_object(TAG.SEQUENCE, CLASS.UNIVERSAL, 1, val)
    end

    encoder[TAG.SET] = function(val)
        return asn1_put_object(TAG.SET, CLASS.UNIVERSAL, 1, val)
    end

    encoder[TAG.BOOLEAN] = function(val)
        -- reject non-booleans: under Lua truthiness 0 is true, so a caller's
        -- 0-for-false would silently encode as TRUE
        if type(val) ~= "boolean" then
            return nil, "BOOLEAN value must be a boolean"
        end
        -- tag(BOOLEAN), length(1), value(TRUE: 0xFF, FALSE: 0)
        return string_char(TAG.BOOLEAN, 1, val and 0xff or 0)
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

        local enc = encoder[tag]
        if not enc then
            -- return an error, not a bare nil callers would concatenate
            return nil, string_format("no encoder for ASN.1 tag %s (value of type %s)",
                                      tostring(tag), type(val))
        end
        return enc(val)
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
        -- validate offsets before they feed pointer arithmetic and omax below
        if type(start) ~= "number" or start < 0 or start % 1 ~= 0
            or type(stop) ~= "number" or stop % 1 ~= 0 then
            return nil, "invalid offset"
        end
        if stop <= start or stop > #der then
            return nil, "invalid offset"
        end

        local s_der = ffi_cast("const unsigned char *", der)
        strpp[0] = s_der + start

        local ret = C.ASN1_get_object(strpp, lenp, tagp, classp, stop - start)
        -- 0x80 signals an encoding error (incl. indefinite/too-long forms)
        if band(ret, 0x80) == 0x80 or band(ret, 0x01) == 0x01 then
            return nil, "invalid BER: bad tag/length encoding"
        end

        -- X.690 s8.1.2.2/s8.1.2.4.2: tags 0..30 must use the low-tag-number form
        -- and forbid a leading 0x80 padding octet. ASN1_get_object normalises the
        -- non-canonical forms to the same tag, so guard them here.
        local id = string_byte(der, start + 1)
        if band(id, 0x1f) == 0x1f then
            if tagp[0] < 31 then
                return nil, "invalid BER: tag <= 30 must use the low-tag-number form"
            end
            if band(string_byte(der, start + 2) or 0, 0x7f) == 0 then
                return nil, "invalid BER: non-canonical tag number padding"
            end
        end

        local content_off = strpp[0] - s_der
        return {
            tag    = tagp[0],
            class  = classp[0],
            len    = tonumber(lenp[0]),
            offset = content_off,           -- 0-indexed content start
            hl     = content_off - start,   -- header length (tag + length octets)
            cons   = band(ret, 0x20) == 0x20,
        }
    end
end
_M.get_object = asn1_get_object


local decode
do
    local decoder = new_tab(0, 5)

    -- required form per universal type (X.690 s8.9.1/s8.11.1, RFC 4511 s5.1);
    -- the wrong form is a BER-smuggling vector against auth parsers
    local CONSTRUCTED_FORM = {
        [TAG.INTEGER]      = false,
        [TAG.OCTET_STRING] = false,
        [TAG.ENUMERATED]   = false,
        [TAG.SEQUENCE]     = true,
        [TAG.SET]          = true,
    }

    local TAG_NAME = {
        [TAG.INTEGER]      = "INTEGER",
        [TAG.OCTET_STRING] = "OCTET STRING",
        [TAG.ENUMERATED]   = "ENUMERATED",
        [TAG.SEQUENCE]     = "SEQUENCE",
        [TAG.SET]          = "SET",
    }

    -- refuse magnitudes a Lua double can't hold exactly; RFC 4511 caps LDAP
    -- integers at 2^31-1 so nothing legitimate is lost. Compared on the int64
    -- cdata, before tonumber() rounds.
    local INT_EXACT_MAX = 9007199254740992LL   -- 2^53

    local function exact_number(v, what)
        if v > INT_EXACT_MAX or v < -INT_EXACT_MAX then
            return nil, what .. " out of representable range"
        end
        return tonumber(v)
    end

    -- OCTET STRING: slice raw content bytes; binary/NUL-safe (no d2i, no strlen)
    decoder[TAG.OCTET_STRING] = function(der, _, obj)
        return string_sub(der, obj.offset + 1, obj.offset + obj.len)
    end

    -- d2i parses a full TLV, so offset is the TLV start. >8 content octets
    -- cannot fit a C long, so the magnitude is out of range.
    decoder[TAG.INTEGER] = function(der, offset, obj)
        if obj.len > 8 then
            return nil, "INTEGER out of representable range"
        end
        cucharpp[0] = ffi_cast("const unsigned char *", der) + offset
        local typ = C.d2i_ASN1_INTEGER(nil, cucharpp, obj.hl + obj.len)
        if typ == nil then
            return nil, "invalid INTEGER encoding"
        end
        local v = C.ASN1_INTEGER_get(typ)
        C.ASN1_INTEGER_free(typ)
        return exact_number(v, "INTEGER")
    end

    decoder[TAG.ENUMERATED] = function(der, offset, obj)
        if obj.len > 8 then
            return nil, "ENUMERATED out of representable range"
        end
        cucharpp[0] = ffi_cast("const unsigned char *", der) + offset
        local typ = C.d2i_ASN1_ENUMERATED(nil, cucharpp, obj.hl + obj.len)
        if typ == nil then
            return nil, "invalid ENUMERATED encoding"
        end
        local v = C.ASN1_ENUMERATED_get(typ)
        C.ASN1_INTEGER_free(typ)   -- shares the ASN1_STRING struct
        return exact_number(v, "ENUMERATED")
    end

    local function decode_children(der, _, obj, depth)
        local stop = obj.offset + obj.len
        local pos = obj.offset
        local values = {}
        local n = 0
        while pos < stop do
            local value, err
            -- bound to the parent's content so an overrunning child cannot
            -- absorb a sibling's bytes without an error
            pos, value, err = decode(der, pos, stop, depth + 1)
            if err then
                return nil, err
            end
            -- decode() never returns a nil value with a nil err, so no holes
            n = n + 1
            values[n] = value
        end
        return values
    end

    decoder[TAG.SEQUENCE] = decode_children
    decoder[TAG.SET]      = decode_children

    -- offset is 0-indexed; stop bounds the TLV to its parent, defaulting to the
    -- whole buffer. Returns next_offset, value, err.
    function decode(der, offset, stop, depth)
        offset = offset or 0
        depth = depth or 0
        if depth > MAX_DECODE_DEPTH then
            return nil, nil, "max decode depth exceeded"
        end
        local obj, err = asn1_get_object(der, offset, stop)
        if not obj then
            return nil, nil, err
        end

        -- dispatch on class + tag + form; tag alone would confuse
        -- context-specific [4]/[16]/[17] with universal types
        if obj.class ~= CLASS.UNIVERSAL then
            return nil, nil, string_format("unsupported element: class 0x%02x tag %d",
                                           obj.class, obj.tag)
        end
        local d = decoder[obj.tag]
        if not d then
            -- error, not a silent nil ("absent" vs "present but unknown")
            return nil, nil, string_format("unsupported ASN.1 tag %d", obj.tag)
        end
        local want_cons = CONSTRUCTED_FORM[obj.tag]
        if obj.cons ~= want_cons then
            return nil, nil, string_format("%s must be %s", TAG_NAME[obj.tag],
                                           want_cons and "constructed" or "primitive")
        end

        local value, derr = d(der, offset, obj, depth)
        if derr then
            return nil, nil, derr
        end
        if value == nil then
            return nil, nil, string_format("%s produced no value", TAG_NAME[obj.tag])
        end
        return obj.offset + obj.len, value
    end
end
_M.decode = decode


return _M
