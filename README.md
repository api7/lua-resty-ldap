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

#### search

**syntax:** *res, err = client:search(base_dn?, scope?, deref_aliases?, size_limit?, time_limit?, types_only?, filter?, attributes?)*

`base_dn` is the base DN you need to search. Default is `dc=example,dc=org`.

`scope` is a flag field in the search protocol that specifies how the LDAP server performs the search, such as baseDN only, all subtrees, etc. You can import those values from protocol.lua, `SEARCH_SCOPE_BASE_OBJECT`, `SEARCH_SCOPE_SINGLE_LEVEL` and `SEARCH_SCOPE_WHOLE_SUBTREE`. Default is `SEARCH_SCOPE_WHOLE_SUBTREE`.

`deref_aliases` is a flag field for setting dereferences, to specifies how the server should treat alias entries that it may encounter during processing. You can import those values from protocol.lua, `SEARCH_DEREF_ALIASES_NEVER`, `SEARCH_DEREF_ALIASES_IN_SEARCHING`, `SEARCH_DEREF_ALIASES_FINDING_BASE_OBJ` amd `SEARCH_DEREF_ALIASES_ALWAYS`. Default is `SEARCH_DEREF_ALIASES_ALWAYS`.

`size_limit` is the maximum number of search request response elements. It is an integer, and its value must be greater than or equal to zero, a value of zero indicates that no size limit is requested. Default is `0`.

`time_limit` is used to specifies the maximum length of time, in seconds, that the server should spend processing the request. It is an integer, and its value must be greater than or equal to zero. A value of zero indicates that no time limit is requested. Default is `0`.

`types_only` indicates whether search result entries should only include attribute descriptions (attribute type names or OIDs, followed by zero or more attribute options), rather than both attribute descriptions and values. This is a Boolean element. Default is `false`.

`filter` is an LDAP filter expression in string. Default is `(objectClass=posixAccount)`.

`attributes` is an array table that contains one to more query fields that you need to have the LDAP server return. Default is `["objectClass"]`.

#### unknown

**syntax:** *res, err = client:unknown(hex_data, multi_resp_hint?)*

`hex_data` is the protocol data connected in hexadecimal, converting ASN.1 binary data directly to hexadecimal. This field is required.

`multi_resp_hint` is a metric used to indicate whether the LDAP response parser is parsing multiple response bodies. Multi-response are typically used in scenarios such as search, where multiple LDAP result data is seamlessly connected. Default is `false`.
