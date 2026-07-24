local asn1            = require("resty.ldap.asn1")
local filter_compiler = require("resty.ldap.filter")
local asn1_put_object = asn1.put_object
local asn1_encode     = asn1.encode
local asn1_get_object = asn1.get_object
local asn1_decode     = asn1.decode
local string_format   = string.format


local _M = {}

local ldapMessageId = 1

local LDAP_MAX_INT = 2147483647

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
    if ldapMessageId > LDAP_MAX_INT then
        ldapMessageId = 1
    end

    return ldapMsg
end


function _M.start_tls_request()
    local methodName = asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, "1.3.6.1.4.1.1466.20037")
    local ldapMsg = ldap_message(_M.APP_NO.ExtendedRequest, methodName)
    return asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)
end


function _M.simple_bind_request(dn, password)
    -- simple [0] OCTET STRING; a zero-length password encodes as `80 00`.
    -- Pin the LDAPString type: put_object rejects a non-string payload, which for
    -- a numeric password would encode an empty (unauthenticated) bind. Coerce
    -- numbers; reject anything else.
    dn = dn == nil and "" or dn
    password = password == nil and "" or password
    if type(dn) == "number" then dn = tostring(dn) end
    if type(password) == "number" then password = tostring(password) end
    if type(dn) ~= "string" then
        return nil, "bind dn must be a string"
    end
    if type(password) ~= "string" then
        return nil, "bind password must be a string"
    end

    local ldapAuth = asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, password)
    local bindReq = asn1_encode(3) .. asn1_encode(dn) .. ldapAuth
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
    -- typesOnly is a BOOLEAN, but callers write 0 for false among the numeric
    -- args; Lua treats 0 as true, so normalise the numeric spelling here
    if types_only == nil or types_only == 0 then
        types_only = false
    elseif type(types_only) == "number" then
        types_only = true
    end

    -- surface asn1.encode's (nil, err) here; the results are concatenated below
    local base_obj, err = asn1_encode(base_obj, asn1.TAG.OCTET_STRING)
    if not base_obj then return nil, err end
    local scope, err = asn1_encode(scope, asn1.TAG.ENUMERATED)
    if not scope then return nil, err end
    local deref_aliases, err = asn1_encode(deref_aliases, asn1.TAG.ENUMERATED)
    if not deref_aliases then return nil, err end
    local size_limit, err = asn1_encode(size_limit, asn1.TAG.INTEGER)
    if not size_limit then return nil, err end
    local time_limit, err = asn1_encode(time_limit, asn1.TAG.INTEGER)
    if not time_limit then return nil, err end
    local types_only, err = asn1_encode(types_only, asn1.TAG.BOOLEAN)
    if not types_only then return nil, err end

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

-- Every decode below passes the enclosing element's end offset, so a field that
-- overruns its parent is rejected instead of swallowing the next field's bytes.

-- decode one element and require the ASN.1 type RFC 4511 assigns to the field;
-- asn1.decode checks class, but the tag must be pinned per field. Returns
-- next_offset, value, err.
local function decode_typed(packet, pos, stop, tag, what)
    local obj, err = asn1_get_object(packet, pos, stop)
    if not obj then return nil, nil, err end
    if obj.class ~= asn1.CLASS.UNIVERSAL or obj.tag ~= tag then
        return nil, nil, string_format("%s has the wrong ASN.1 type (class 0x%02x tag %d)",
                                       what, obj.class, obj.tag)
    end
    return asn1_decode(packet, pos, stop)
end

-- hand-walked containers skip asn1.decode's dispatch, so assert their form here
local function is_sequence(obj)
    return obj.class == asn1.CLASS.UNIVERSAL
       and obj.tag == asn1.TAG.SEQUENCE
       and obj.cons
end

-- protocolOp tags a server may send; anything else must not reach parse_ldap_result
local LDAP_RESULT_OPS = {
    [_M.APP_NO.BindResponse]     = true,
    [_M.APP_NO.SearchResultDone] = true,
    [_M.APP_NO.ModifyResponse]   = true,
    [_M.APP_NO.ExtendedResponse] = true,
}

local function parse_ldap_result(packet, op, res)
    -- RFC 4511 s4.1.9: LDAPResult ::= SEQUENCE { resultCode ENUMERATED,
    -- matchedDN LDAPDN, diagnosticMessage LDAPString, referral [3] OPTIONAL }
    local stop = op.offset + op.len
    local _, pos, code, matched_dn, diag, err
    pos, code, err = decode_typed(packet, op.offset, stop,
                                  asn1.TAG.ENUMERATED, "resultCode")
    if err then return nil, err end
    pos, matched_dn, err = decode_typed(packet, pos, stop,
                                        asn1.TAG.OCTET_STRING, "matchedDN")
    if err then return nil, err end
    _, diag, err = decode_typed(packet, pos, stop,
                                asn1.TAG.OCTET_STRING, "diagnosticMessage")
    if err then return nil, err end
    res.result_code = code
    res.matched_dn = matched_dn
    res.diagnostic_msg = diag
    -- no whole-op check: optional trailing fields (referral [3], SASL creds,
    -- responseName/Value) legally follow and AD emits them constantly
    return res
end

local function parse_search_entry(packet, op, res)
    -- RFC 4511 s4.5.2: SearchResultEntry ::= [APPLICATION 4] SEQUENCE
    --   { objectName LDAPDN, attributes PartialAttributeList }
    local stop = op.offset + op.len
    local pos, entry_dn, err
    pos, entry_dn, err = decode_typed(packet, op.offset, stop,
                                      asn1.TAG.OCTET_STRING, "objectName")
    if err then return nil, err end
    res.entry_dn = entry_dn

    -- PartialAttributeList ::= SEQUENCE OF PartialAttribute
    local attrs, aerr = asn1_get_object(packet, pos, stop)
    if not attrs then return nil, aerr end
    if not is_sequence(attrs) then
        return nil, "PartialAttributeList is not a universal constructed SEQUENCE"
    end

    local attributes = {}
    local apos = attrs.offset
    local astop = attrs.offset + attrs.len
    while apos < astop do
        -- PartialAttribute ::= SEQUENCE { type AttributeDescription,
        --                                 vals SET OF AttributeValue }
        local pa, perr = asn1_get_object(packet, apos, astop)
        if not pa then return nil, perr end
        if not is_sequence(pa) then
            return nil, "PartialAttribute is not a universal constructed SEQUENCE"
        end
        local pastop = pa.offset + pa.len
        -- becomes a table key, so its string type is load-bearing
        local vpos, atype, terr = decode_typed(packet, pa.offset, pastop,
                                               asn1.TAG.OCTET_STRING,
                                               "AttributeDescription")
        if terr then return nil, terr end
        -- vals is a SET OF: enforce it so the stored value is always an array
        local _, vals, verr = decode_typed(packet, vpos, pastop,
                                           asn1.TAG.SET, "attribute vals")
        if verr then return nil, verr end
        attributes[atype] = vals                 -- ALWAYS an array (empty for typesOnly)
        apos = pastop
    end
    -- SearchResultEntry has exactly two components; nothing may follow
    if astop ~= stop then
        return nil, "trailing bytes in SearchResultEntry"
    end
    res.attributes = attributes
    return res
end

local function parse_search_reference(packet, op, res)
    -- [APPLICATION 19] IMPLICIT replaces the SEQUENCE OF tag, so `op` IS the
    -- sequence. RFC 4511 s4.5.2: SearchResultReference ::= [APPLICATION 19]
    -- SEQUENCE SIZE (1..MAX) OF uri URI, with URI ::= LDAPString (s4.1.10).
    local uris = {}
    local n = 0
    local pos = op.offset
    local stop = op.offset + op.len
    while pos < stop do
        local uri, err
        pos, uri, err = decode_typed(packet, pos, stop, asn1.TAG.OCTET_STRING,
                                     "SearchResultReference URI")
        if err then return nil, err end
        n = n + 1
        uris[n] = uri
    end
    res.uris = uris
    return res
end

function _M.decode_message(packet)
    local env, err = asn1_get_object(packet, 0)
    if not env then return nil, err end
    -- LDAPMessage is a constructed SEQUENCE (X.690 s8.9.1)
    if not is_sequence(env) then
        return nil, "invalid LDAPMessage envelope"
    end

    local envstop = env.offset + env.len
    -- the envelope must account for every byte; trailing data is a second
    -- message or garbage that would otherwise be silently discarded
    if envstop ~= #packet then
        return nil, "trailing bytes after LDAPMessage"
    end

    -- messageID ::= INTEGER (0..maxInt), RFC 4511 s4.1.1
    local pos, message_id, merr = decode_typed(packet, env.offset, envstop,
                                               asn1.TAG.INTEGER, "messageID")
    if merr then return nil, merr end

    local op, oerr = asn1_get_object(packet, pos, envstop)                  -- protocolOp
    if not op then return nil, oerr end
    if op.class ~= asn1.CLASS.APPLICATION then
        return nil, "protocolOp is not APPLICATION-tagged"
    end
    -- every response protocolOp is a constructed SEQUENCE
    if not op.cons then
        return nil, "protocolOp is not constructed"
    end

    -- exactly one protocolOp per LDAPMessage; only controls [0] may follow it
    -- (RFC 4511 s4.1.1). A second APPLICATION element is smuggled data.
    local opend = op.offset + op.len
    if opend ~= envstop then
        local ctrl, cerr = asn1_get_object(packet, opend, envstop)
        if not ctrl then return nil, cerr end
        if ctrl.class ~= asn1.CLASS.CONTEXT_SPECIFIC or ctrl.tag ~= 0 then
            return nil, "unexpected element after protocolOp"
        end
        if ctrl.offset + ctrl.len ~= envstop then
            return nil, "trailing bytes after controls"
        end
    end

    local res = { message_id = message_id, protocol_op = op.tag }

    if op.tag == _M.APP_NO.SearchResultEntry then
        return parse_search_entry(packet, op, res)
    elseif op.tag == _M.APP_NO.SearchResultReference then
        return parse_search_reference(packet, op, res)
    elseif LDAP_RESULT_OPS[op.tag] then
        return parse_ldap_result(packet, op, res)
    end
    return nil, "unsupported protocolOp " .. op.tag
end


return _M
