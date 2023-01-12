local string_char     = string.char
local asn1            = require "resty.ldap.asn1"
local asn1_put_object = asn1.put_object
local asn1_encode     = asn1.encode


local _M = {}

local ldapMessageId = 1

_M.ERROR_MSG = {
    [1]  = "Initialization of LDAP library failed.",
    [4]  = "Size limit exceeded.",
    [13] = "Confidentiality required",
    [32] = "No such object",
    [34] = "Invalid DN",
    [49] = "The supplied credential is invalid."
}

_M.APP_NO = {
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
    ExtendedRequest = 23,
    ExtendedResponse = 24
}


local function ldap_message(app_no, req)
    local ldapMsg = asn1_encode(ldapMessageId) ..
        asn1_put_object(app_no, asn1.CLASS.APPLICATION, 1, req)

    ldapMessageId = ldapMessageId + 1

    return ldapMsg
end


function _M.simple_bind_request(dn, password)
    local ldapAuth = asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, password or "")
    if not password then
        -- When password is nil, ASN1_put_object does not generate a zero length for it,
        -- so we need to fill it in manually.
        -- This is a compatibility measure for anonymous bind.
        ldapAuth = ldapAuth .. string_char(0)
    end
    local bindReq = asn1_encode(3) .. asn1_encode(dn or "") .. ldapAuth
    local ldapMsg = ldap_message(_M.APP_NO.BindRequest, bindReq)
    return asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)
end


function _M.search_request(base_obj)
    local base_object = asn1_encode(base_obj, asn1.TAG.OCTET_STRING)
    local scope = asn1_encode(2, asn1.TAG.ENUMERATED)
    local derefAliases = asn1_encode(0, asn1.TAG.ENUMERATED)
    local sizeLimit = asn1_encode(0, asn1.TAG.INTEGER)
    local timeLimit = asn1_encode(0, asn1.TAG.INTEGER)
    local typesOnly = asn1_encode(false, asn1.TAG.BOOLEAN)
    --local filter = asn1_put_object(7, asn1.CLASS.CONTEXT_SPECIFIC, 0, "objectClass")
    local filter = asn1_put_object(8, asn1.CLASS.CONTEXT_SPECIFIC, 0, asn1_encode("uid")..asn1_encode("user*"))
    local attributes = asn1_encode("uid")..asn1_encode("uidNumber")
    local attributes_seq = asn1_encode(attributes, asn1.TAG.SEQUENCE)

    local searchReq = base_object .. scope .. derefAliases .. sizeLimit ..
        timeLimit .. typesOnly .. filter .. attributes_seq
    local ldapMsg = ldap_message(_M.APP_NO.SearchRequest, searchReq)
    return asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)
end


return _M
