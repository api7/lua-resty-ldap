# lua-resty-ldap: ldap auth lib

Access ldap server to do authentication via cosocket.

This project is extracted from [kong](https://github.com/Kong/kong/tree/master/kong/plugins/ldap-auth).

## Installation

The preferred way to install this library is to use Luarocks:

```shell
luarocks install lua-resty-ldap

```

## Synopsis

```lua
local ldap = require("resty.ldap")
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

```lua
local ldap_client = require("resty.ldap.client")
local client = ldap_client:new("127.0.0.1", 1389, {
    socket_timeout = 10000,
    keepalive_timeout = 60000,
    start_tls = false,
    ldaps = false,
    ssl_verify = false
})
local err = client:simple_bind("cn=user01,ou=users,dc=example,dc=org", "password1")
```

## Modules

### resty.ldap

To load this module:

```lua
    local ldap = require "resty.ldap"
```

#### ldap_authenticate

**syntax:** *res, err = ldap.ldap_authenticate(username, password, ldapconf)*

`ldapconf` is a table of below items:

| key      | type | default value      | Description |
| ----------- | ----------- | ----------- | ----------- |
| `ldap_host`      | string       | "localhost"      | Host on which the LDAP server is running.       |
| `ldap_port`      | number       | 389      | TCP port where the LDAP server is listening. 389 is the default port for non-SSL LDAP and AD. 636 is the port required for SSL LDAP and AD. If ldaps is configured, you must use port 636.       |
| `start_tls`      | boolean       | false      | Set it to `true` to issue StartTLS (Transport Layer Security) extended operation over ldap connection. If the start_tls setting is enabled, ensure the ldaps setting is disabled.       |
| `ldaps`      | boolean       | false      | Set to `true` to connect using the LDAPS protocol (LDAP over TLS). When ldaps is configured, you must use port 636. If the ldap setting is enabled, ensure the start_tls setting is disabled.       |
| `base_dn`      | string       | "ou=users,dc=example,dc=org"      | Base DN as the starting point for the search; e.g., “dc=example,dc=com”.       |
| `verify_ldap_host`      | boolean       | false      | Set to true to authenticate LDAP server. The server certificate will be verified according to the CA certificates specified by the `lua_ssl_trusted_certificate` directive.       |
| `attribute`      | string       | "cn"      | Attribute to be used to search the user; e.g., “cn”.       |
| `timeout`      | number       | 10000      | An optional timeout in milliseconds when waiting for connection with LDAP server.       |
| `keepalive`      | number       | 60000      | An optional value in milliseconds that defines how long an idle connection to LDAP server will live before being closed.       |

### resty.ldap.client

To load this module:

```lua
    local ldap_client = require "resty.ldap.client"
```

#### new

**syntax:** *client = ldap_client:new(host, port, client_config?)*

`client_config` is a table of below items, it is optional:

| key      | type | default value      | Description |
| ----------- | ----------- | ----------- | ----------- |
| `socket_timeout`      | number       | 10000      | An optional timeout in milliseconds when waiting for connection with LDAP server.       |
| `keepalive_timeout`   | number       | 60000      | An optional value in milliseconds that defines how long an idle connection to LDAP server will live before being closed.       |
| `start_tls`      | boolean       | false      | Set it to `true` to issue StartTLS (Transport Layer Security) extended operation over ldap connection. If the start_tls setting is enabled, ensure the ldaps setting is disabled.       |
| `ldaps`      | boolean       | false      | Set to `true` to connect using the LDAPS protocol (LDAP over TLS). When ldaps is configured, you must use port 636. If the ldap setting is enabled, ensure the start_tls setting is disabled.       |
| `ssl_verify`      | boolean       | false      | Set to true to authenticate LDAP server. The server certificate will be verified according to the CA certificates specified by the `lua_ssl_trusted_certificate` directive.       |

#### simple_bind

**syntax:** *res, err = client:simple_bind(bind_dn?, password?)*

`bind_dn` is the full DN you need to bind.

`password` is generally the `userPassword` field stored in that DN, but this is the mechanism implemented by the directory server.

`bind_dn` and `password` can be `nil` values, that means the client is instructed to do anonymous bind.

`res` is a boolean type value that will be true when authentication is successful, when it is false, `err` will contain errors.
