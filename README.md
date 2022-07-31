lua-resty-ldap: ldap auth lib
===========================================

Access ldap server to do authentication via cosocket.

This project is extracted from [kong](https://github.com/Kong/kong/tree/master/kong/plugins/ldap-auth).

Installation
------------

The preferred way to install this library is to use Luarocks:

    luarocks install lua-resty-ldap

Usage
-----

### Getting started

Example:

```lua
local ldap = require "resty.ldap"
local ldapconf = {
    timeout = 10000,
    start_tls = false,
    ldap_host = "127.0.0.1",
    ldap_port = 1389,
    ldaps = false,
    verify_ldap_host = false,
    base_dn = "ou=users,dc=example,dc=org",
    attribute = "cn",
    keepalive = 60000,
}
local res, err = ldap.ldap_authenticate("john", "abc", ldapconf)
```
