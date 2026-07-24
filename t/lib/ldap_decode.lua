local ok, rasn = pcall(require, "rasn")
if ok and type(rasn) == "table" and rasn.decode_ldap then
    return rasn.decode_ldap
end
return require("resty.ldap.protocol").decode_message
