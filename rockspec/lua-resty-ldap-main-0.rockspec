package = "lua-resty-ldap"
version = "main-0"
source = {
   url = "git://github.com/api7/lua-resty-ldap",
   branch = "main",
}

description = {
   summary = "Nonblocking Lua ldap driver library for OpenResty",
   homepage = "https://github.com/iresty/lua-resty-ldap",
   license = "Apache License 2.0",
   maintainer = "Yuansheng Wang <membphis@gmail.com>"
}

dependencies = {
   "lua_pack = 2.0.0-0"
   "lpeg = 1.0.2-1"
   "lua-resty-string = 0.09-0"
}

build = {
   type = "builtin",
   modules = {
    ["resty.ldap"] = "lib/resty/ldap/init.lua",
    ["resty.ldap.asn1"] = "lib/resty/ldap/asn1.lua",
    ["resty.ldap.ldap"] = "lib/resty/ldap/ldap.lua",
   }
}
