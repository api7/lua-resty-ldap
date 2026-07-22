local asn1     = require("resty.ldap.asn1")
local protocol = require("resty.ldap.protocol")
local bunpack  = require("lua_pack").unpack
local fmt      = string.format
local decode_ldap     = protocol.decode_message
local asn1_put_object = asn1.put_object
local asn1_encode     = asn1.encode


local _M = {}


local ldapMessageId = 1


local ERROR_MSG = {
    [1]  = "Initialization of LDAP library failed.",
    [4]  = "Size limit exceeded.",
    [13] = "Confidentiality required",
    [32] = "No such object",
    [34] = "Invalid DN",
    [49] = "The supplied credential is invalid."
}


local APPNO = {
    BindRequest = 0,
    BindResponse = 1,
    UnbindRequest = 2,
    ExtendedRequest = 23,
    ExtendedResponse = 24
}


-- A legal length such as 84 7f ff ff ff would force a multi-GiB allocation in
-- the worker. 16 MiB comfortably exceeds any real entry.
local MAX_LDAP_MESSAGE_SIZE = 16 * 1024 * 1024


-- Returns the body length and the header bytes, or nil plus an error. Both
-- callers receive() the length while still in cleartext, so validate it here.
local function calculate_payload_length(encStr, pos, socket)
    local elen

    pos, elen = bunpack(encStr, "C", pos)

    -- 0x80 is the indefinite form and 0xff is reserved; RFC 4511 s5.1 requires
    -- the definite form. Neither is a 128-byte short-form length.
    if elen == 0x80 or elen == 0xff then
        return nil, nil, "invalid BER length: indefinite or reserved form"
    end

    if elen > 128 then
        elen = elen - 128
        local elenCalc = 0
        local elenNext

        for _ = 1, elen do
            elenCalc = elenCalc * 256
            local byte, err = socket:receive(1)
            if not byte then
                return nil, nil, fmt("receive length header failed: %s", err)
            end
            encStr = encStr .. byte
            pos, elenNext = bunpack(encStr, "C", pos)
            elenCalc = elenCalc + elenNext
        end

        elen = elenCalc
    end

    if elen > MAX_LDAP_MESSAGE_SIZE then
        return nil, nil, fmt("ldap message too large: %d bytes", elen)
    end

    return elen, encStr
end


function _M.bind_request(socket, username, password)
    -- pin the LDAPString type: put_object rejects a non-string payload, so
    -- catch it here rather than as a concat error on the next line
    if type(username) == "number" then username = tostring(username) end
    if type(password) == "number" then password = tostring(password) end
    if type(username) ~= "string" then
        return false, "bind username must be a string"
    end
    if type(password) ~= "string" then
        return false, "bind password must be a string"
    end

    local ldapAuth = asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, password)
    local bindReq = asn1_encode(3) .. asn1_encode(username) .. ldapAuth
    local ldapMsg = asn1_encode(ldapMessageId) ..
                        asn1_put_object(APPNO.BindRequest, asn1.CLASS.APPLICATION, 1, bindReq)

    local packet = asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)

    ldapMessageId = ldapMessageId + 1

    local bytes, err = socket:send(packet)
    if not bytes then
        socket:close()
        return nil, fmt("send bind request failed: %s", err or "closed")
    end

    local header, herr = socket:receive(2)
    if not header then
        socket:close()
        return nil, fmt("receive bind response header failed: %s", herr or "closed")
    end

    local packet_len, packet_header, lerr = calculate_payload_length(header, 2, socket)
    if not packet_len then
        socket:close()
        return nil, lerr
    end

    local body, berr = socket:receive(packet_len)
    if not body then
        socket:close()
        return nil, fmt("receive bind response body failed: %s", berr or "closed")
    end

    -- decode_message expects the full LDAPMessage, envelope header included
    local res, derr = decode_ldap(packet_header .. body)
    if derr then
        socket:close()
        return nil, "Invalid LDAP message encoding: " .. derr
    end

    if res.protocol_op ~= APPNO.BindResponse then
        socket:close()
        return nil, fmt("Received incorrect Op in packet: %d, expected %d",
                          res.protocol_op, APPNO.BindResponse)
    end

    if res.result_code ~= 0 then
        local error_msg = ERROR_MSG[res.result_code]

        return false, fmt("\n  Error: %s\n  Details: %s",
                          error_msg or "Unknown error occurred (code: " ..
                          res.result_code .. ")", res.diagnostic_msg or "")

    else
        return true
    end
end


function _M.unbind_request(socket)
    local ldapMsg, packet

    ldapMessageId = ldapMessageId + 1

    ldapMsg = asn1_encode(ldapMessageId) ..
                asn1_put_object(APPNO.UnbindRequest, asn1.CLASS.APPLICATION, 0)
    packet = asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)

    local bytes, err = socket:send(packet)
    if not bytes then
        socket:close()
        return nil, fmt("send unbind request failed: %s", err or "closed")
    end

    return true, ""
end


function _M.start_tls(socket)
    local method_name = asn1_put_object(0, asn1.CLASS.CONTEXT_SPECIFIC, 0, "1.3.6.1.4.1.1466.20037")

    ldapMessageId = ldapMessageId + 1

    local ldapMsg = asn1_encode(ldapMessageId) ..
                asn1_put_object(APPNO.ExtendedRequest, asn1.CLASS.APPLICATION, 1, method_name)

    local packet = asn1_encode(ldapMsg, asn1.TAG.SEQUENCE)

    local bytes, err = socket:send(packet)
    if not bytes then
        socket:close()
        return false, fmt("send STARTTLS request failed: %s", err or "closed")
    end

    local header, herr = socket:receive(2)
    if not header then
        socket:close()
        return false, fmt("receive STARTTLS response header failed: %s", herr or "closed")
    end

    local packet_len, packet_header, lerr = calculate_payload_length(header, 2, socket)
    if not packet_len then
        socket:close()
        return false, lerr
    end

    local body, berr = socket:receive(packet_len)
    if not body then
        socket:close()
        return false, fmt("receive STARTTLS response body failed: %s", berr or "closed")
    end

    -- decode_message expects the full LDAPMessage, envelope header included
    local res, derr = decode_ldap(packet_header .. body)
    if derr then
        socket:close()
        return false, "Invalid LDAP message encoding: " .. derr
    end

    if res.protocol_op ~= APPNO.ExtendedResponse then
        socket:close()
        return false, fmt("Received incorrect Op in packet: %d, expected %d",
                          res.protocol_op, APPNO.ExtendedResponse)
    end

    if res.result_code ~= 0 then
        socket:close()
        local error_msg = ERROR_MSG[res.result_code]

        return false, fmt("\n  Error: %s\n  Details: %s",
                          error_msg or "Unknown error occurred (code: " ..
                          res.result_code .. ")", res.diagnostic_msg or "")

    else
        return true
    end
end


return _M
