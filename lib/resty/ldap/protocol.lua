local asn1            = require("resty.ldap.asn1")
local filter_compiler = require("resty.ldap.filter")
local asn1_put_object = asn1.put_object
local asn1_encode     = asn1.encode
local asn1_get_object = asn1.get_object
local asn1_decode     = asn1.decode
local table_insert    = table.insert


local _M = {}

local ldapMessageId = 1

_M.ERROR_MSG = {
    [1]  = "Initialization of LDAP library failed",
    [4]  = "Size limit exceeded",
    [13] = "Confidentiality required",
    [32] = "No such object",
    [34] = "Invalid DN",
    [49] = "The supplied credential is invalid"
}

_M.APP_NO = {
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
    ModifyResponse = 7,
    SearchResultReference = 19,
    ExtendedRequest = 23,
    ExtendedResponse = 24
}


local function ldap_message(app_no, req)
    local ldapMsg = asn1_encode(ldapMessageId) ..
        asn1_put_object(app_no, asn1.CLASS.APPLICATION, 1, req)

    ldapMessageId = ldapMessageId + 1

    return ldapMsg
end


function _M.start_tls_request()
    local methodName = asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, "1.3.6.1.4.1.1466.20037")
    local ldapMsg = ldap_message(_M.APP_NO.ExtendedRequest, methodName)
    return asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)
end


function _M.simple_bind_request(dn, password)
    -- simple [0] OCTET STRING; a zero-length password (anonymous/unauthenticated
    -- bind) now encodes correctly as `80 00` since asn1.put_object no longer
    -- truncates the length octet.
    local ldapAuth = asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, password or "")
    local bindReq = asn1_encode(3) .. asn1_encode(dn or "") .. ldapAuth
    local ldapMsg = ldap_message(_M.APP_NO.BindRequest, bindReq)
    return asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)
end


_M.SEARCH_SCOPE_BASE_OBJECT = 0
_M.SEARCH_SCOPE_SINGLE_LEVEL = 1
_M.SEARCH_SCOPE_WHOLE_SUBTREE = 2
_M.SEARCH_DEREF_ALIASES_NEVER = 0
_M.SEARCH_DEREF_ALIASES_IN_SEARCHING = 1
_M.SEARCH_DEREF_ALIASES_FINDING_BASE_OBJ = 2
_M.SEARCH_DEREF_ALIASES_ALWAYS = 3

-- protocol reference: https://ldap.com/ldapv3-wire-protocol-reference-search/
local function build_asn1_filter(filter)
    local item_type = filter.item_type
    local filter_type = filter.filter_type
    local attribute_description = filter.attribute_description
    local attribute_value = filter.attribute_value

    if item_type == filter_compiler.ITEM_TYPE_SIMPLE then
        local body = asn1_encode(attribute_description) .. asn1_encode(attribute_value)
        if filter_type == filter_compiler.FILTER_TYPE_EQUAL then
            return asn1_put_object(3, asn1.CLASS.CONTEXT_SPECIFIC, 1, body)
        elseif filter_type == filter_compiler.FILTER_TYPE_APPROX then
            return asn1_put_object(8, asn1.CLASS.CONTEXT_SPECIFIC, 1, body)
        elseif filter_type == filter_compiler.FILTER_TYPE_GREATER then
            return asn1_put_object(5, asn1.CLASS.CONTEXT_SPECIFIC, 1, body)
        elseif filter_type == filter_compiler.FILTER_TYPE_LESS then
            return asn1_put_object(6, asn1.CLASS.CONTEXT_SPECIFIC, 1, body)
        end
    elseif item_type == filter_compiler.ITEM_TYPE_PRESENT then
        -- present is a special case, it uses primitive instead of
        -- constructed, the rest of several are constructed.
        return asn1_put_object(7, asn1.CLASS.CONTEXT_SPECIFIC, 0, attribute_description)
    elseif item_type == filter_compiler.ITEM_TYPE_SUBSTRING then
        local body = ""
        local attribute_value_len = #attribute_value

        for index, value in ipairs(attribute_value) do
            if index == 1 and value ~= "*" then -- initial
                -- This means that the values do not start with *,
                -- so we need to use the initial field in the substring filter.
                body = body .. asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, value)
            elseif index == attribute_value_len and value ~= "*" then -- final
                -- This means that the values do not start with *,
                -- so we need to use the final field in the substring filter.
                body = body .. asn1_put_object(2, asn1.CLASS.CONTEXT_SPECIFIC, 0, value)
            elseif value ~= "*" then -- any
                body = body .. asn1_put_object(1, asn1.CLASS.CONTEXT_SPECIFIC, 0, value)
            end
        end
        return asn1_put_object(4, asn1.CLASS.CONTEXT_SPECIFIC, 1,
                   asn1_encode(attribute_description) ..
                   asn1_encode(body, asn1.TAG.SEQUENCE)
               )
    end

    return ""
end

local function build_asn1_filters(filter_tbl)
    -- The final-level filter object, which expresses an actual
    -- expression rather than a set of logical relations.
    if not filter_tbl.op_type and filter_tbl.item_type then
        -- Since this function is used for recursive calls,
        -- it returns directly when the endmost node of the filter tree is encountered.
        return build_asn1_filter(filter_tbl)
    end

    if filter_tbl.op_type and filter_tbl.op_type == filter_compiler.OP_TYPE_NOT and
        filter_tbl.items and #filter_tbl.items == 1 then
        return asn1_put_object(
                    2, -- not 2
                    asn1.CLASS.CONTEXT_SPECIFIC, 1,
                    build_asn1_filter(filter_tbl.items[1])
               )
    end

    if filter_tbl.op_type and filter_tbl.items and #filter_tbl.items > 1 then
        local sub_filter = ''
        for _, item in ipairs(filter_tbl.items) do
            sub_filter = sub_filter .. build_asn1_filters(item)
        end

        return asn1_put_object(
                    filter_tbl.op_type == filter_compiler.OP_TYPE_AND and 0 or 1, -- 'and' 0 or 'or' 1
                    asn1.CLASS.CONTEXT_SPECIFIC, 1,
                    sub_filter
               )
    end

    -- Provide a default filter, i.e. (objectClass=*)
    return asn1_put_object(3, asn1.CLASS.CONTEXT_SPECIFIC, 1,
               asn1_encode("objectClass") ..
               asn1_encode("*")
           )
end

function _M.search_request(base_obj, scope, deref_aliases, size_limit, time_limit,
                           types_only, filter, attributes)
    local base_obj = asn1_encode(base_obj, asn1.TAG.OCTET_STRING)
    local scope = asn1_encode(scope, asn1.TAG.ENUMERATED)
    local deref_aliases = asn1_encode(deref_aliases, asn1.TAG.ENUMERATED)
    local size_limit = asn1_encode(size_limit, asn1.TAG.INTEGER)
    local time_limit = asn1_encode(time_limit, asn1.TAG.INTEGER)
    local types_only = asn1_encode(types_only, asn1.TAG.BOOLEAN)

    -- compile filter
    local filter_tbl, err = filter_compiler.compile(filter)
    if not filter_tbl then
        return nil, err
    end
    local filter = build_asn1_filters(filter_tbl)

    -- encode attributes to sequence
    local attributes_encoded = ""
    for _, attribute in ipairs(attributes) do
        attributes_encoded = attributes_encoded .. asn1_encode(tostring(attribute))
    end
    local attributes_seq = asn1_encode(attributes_encoded, asn1.TAG.SEQUENCE)

    local searchReq = base_obj .. scope .. deref_aliases .. size_limit ..
        time_limit .. types_only .. filter .. attributes_seq
    local ldapMsg = ldap_message(_M.APP_NO.SearchRequest, searchReq)
    return asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)
end


-- Response decoding.

local function parse_ldap_result(packet, op, res)
    local pos, code, matched_dn, diag, err
    pos, code, err = asn1_decode(packet, op.offset)      -- resultCode ENUMERATED
    if err then return nil, err end
    res.result_code = code
    pos, matched_dn, err = asn1_decode(packet, pos)      -- matchedDN OCTET STRING
    if err then return nil, err end
    res.matched_dn = matched_dn
    _, diag, err = asn1_decode(packet, pos)              -- diagnosticMessage OCTET STRING
    if err then return nil, err end
    res.diagnostic_msg = diag
    return res
end

local function parse_search_entry(packet, op, res)
    local pos, entry_dn, err
    pos, entry_dn, err = asn1_decode(packet, op.offset)  -- objectName
    if err then return nil, err end
    res.entry_dn = entry_dn

    local attrs, aerr = asn1_get_object(packet, pos)     -- PartialAttributeList (SEQUENCE OF)
    if not attrs then return nil, aerr end

    local attributes = {}
    local apos = attrs.offset
    local astop = attrs.offset + attrs.len
    while apos < astop do
        local pa, perr = asn1_get_object(packet, apos)   -- PartialAttribute SEQUENCE
        if not pa then return nil, perr end
        local vpos, atype, terr = asn1_decode(packet, pa.offset)   -- type
        if terr then return nil, terr end
        local _, vals, verr = asn1_decode(packet, vpos)            -- vals SET OF -> array
        if verr then return nil, verr end
        attributes[atype] = vals or {}                   -- ALWAYS an array (empty for typesOnly)
        apos = pa.offset + pa.len
    end
    res.attributes = attributes
    return res
end

local function parse_search_reference(packet, op, res)
    -- [APPLICATION 19] IMPLICIT replaces the SEQUENCE OF tag, so `op` IS the sequence.
    local uris = {}
    local pos = op.offset
    local stop = op.offset + op.len
    while pos < stop do
        local uri, err
        pos, uri, err = asn1_decode(packet, pos)
        if err then return nil, err end
        table_insert(uris, uri)
    end
    res.uris = uris
    return res
end

function _M.decode_message(packet)
    local env, err = asn1_get_object(packet, 0)
    if not env then return nil, err end
    if env.tag ~= asn1.TAG.SEQUENCE or env.class ~= asn1.CLASS.UNIVERSAL then
        return nil, "invalid LDAPMessage envelope"
    end

    local pos, message_id, merr = asn1_decode(packet, env.offset)   -- messageID
    if merr then return nil, merr end

    local op, oerr = asn1_get_object(packet, pos)                   -- protocolOp
    if not op then return nil, oerr end
    if op.class ~= asn1.CLASS.APPLICATION then
        return nil, "protocolOp is not APPLICATION-tagged"
    end

    local res = { message_id = message_id, protocol_op = op.tag }

    if op.tag == _M.APP_NO.SearchResultEntry then
        return parse_search_entry(packet, op, res)
    elseif op.tag == _M.APP_NO.SearchResultReference then
        return parse_search_reference(packet, op, res)
    else
        -- LDAPResult-shaped ops: BindResponse, SearchResultDone, ModifyResponse, ExtendedResponse
        return parse_ldap_result(packet, op, res)
    end
end


return _M
