package = "lua-resty-ldap"
version = "local-0"
source = {
   url = "file://."
}

description = {
   summary = "Nonblocking Lua ldap driver library for OpenResty",
   homepage = "https://github.com/api7/lua-resty-ldap",
   license = "Apache License 2.0",
   maintainer = "Yuansheng Wang <membphis@gmail.com>"
}

dependencies = {
   "lua_pack = 2.0.0-0",
   "lpeg = 1.0.2-1",
}

build = {
   type = "builtin",
   modules = {
      ["resty.ldap.asn1"]     = "lib/resty/ldap/asn1.lua",
      ["resty.ldap.filter"]   = "lib/resty/ldap/filter.lua",
      ["resty.ldap.protocol"] = "lib/resty/ldap/protocol.lua",
      ["resty.ldap.client"]   = "lib/resty/ldap/client.lua",
   }
}
