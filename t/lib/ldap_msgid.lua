-- Decode the messageID INTEGER out of an encoded LDAPMessage packet.
local asn1 = require("resty.ldap.asn1")

return function(packet)
    local env = assert(asn1.get_object(packet, 0))
    local _, id = asn1.decode(packet, env.offset, env.offset + env.len)
    return id
end
