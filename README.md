# lua-resty-ldap: ldap client lib

Access ldap server via cosocket.

A small part of the code in this project came from [kong](https://github.com/Kong/kong/tree/master/kong/plugins/ldap-auth) and most of them are being refactored.

## Installation

The preferred way to install this library is to use Luarocks:

```shell
luarocks install lua-resty-ldap

```

## Synopsis

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
| `start_tls`           | boolean      | false      | Set it to `true` to issue StartTLS (Transport Layer Security) extended operation over ldap connection. If the start_tls setting is enabled, ensure the ldaps setting is disabled.       |
| `ldaps`               | boolean      | false      | Set to `true` to connect using the LDAPS protocol (LDAP over TLS). When ldaps is configured, you must use port 636. If the ldap setting is enabled, ensure the start_tls setting is disabled.       |
| `ssl_verify`          | boolean      | false      | Set to true to authenticate LDAP server. The server certificate will be verified according to the CA certificates specified by the `lua_ssl_trusted_certificate` directive.       |
| `keepalive_pool_name`           | string       | host:ip  | Set and override the default connection pool name for scenarios where the same connection parameters are used but with a different authentication method. The default value is the same as the OpenResty rule, and the value is the `host:port` of the LDAP server. |
| `keepalive_pool_size`           | number       | 2          | Set the size of a certain connection pool. According to OpenResty's rule, it can only be set when the pool is created and cannot be changed dynamically. |

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

`filter` is an LDAP filter expression in string. Default is `(objectClass=*)`.

`attributes` is an array table that contains one to more query fields that you need to have the LDAP server return. Default is `["objectClass"]`.

#### connect

**syntax:** *ok, err = client:connect()*

Establishes and pins the underlying connection, so that subsequent operations on this client (for example a `simple_bind` followed by a `search`) run on that same connection instead of each drawing one from the connection pool. Release the connection with `set_keepalive` or `close` when done.

An unrecoverable socket error also releases the pin, so the next operation draws a fresh connection instead of reusing the dead one.

#### set_keepalive

**syntax:** *ok, err = client:set_keepalive()*

Releases a pinned connection back into the connection pool. The client remains usable; subsequent operations draw pooled connections as before.

#### close

**syntax:** *ok, err = client:close()*

Closes a pinned connection without returning it to the pool.

### resty.ldap

Compatibility entrypoint kept for APISIX's `ldap-auth` plugin (restored from v0.1.0). New code should use `resty.ldap.client` instead.

```lua
    local ldap = require "resty.ldap"
```

#### ldap_authenticate

**syntax:** *ok, err = ldap.ldap_authenticate(username, password, conf)*

Binds against the directory as `<attribute>=<username>,<base_dn>` with the given password. `ok` is `true` when authentication succeeds; otherwise `ok` is `false` or `nil` and `err` carries the error.

`username` is RFC 4514-escaped before being placed in the DN, so DN metacharacters bind as literal characters instead of injecting extra RDN components.

`conf` is a table of below items (note the key names differ from `resty.ldap.client`'s `client_config`; they follow the v0.1.0 / `ldap-auth` contract):

| key      | type | default value      | Description |
| ----------- | ----------- | ----------- | ----------- |
| `ldap_host`           | string       | localhost  | LDAP server host. |
| `ldap_port`           | number       | 389        | LDAP server port. |
| `timeout`             | number       | 10000      | Socket timeout in milliseconds. |
| `keepalive`           | number       | 60000      | Connection pool keepalive in milliseconds. |
| `start_tls`           | boolean      | false      | Issue the StartTLS extended operation before binding. |
| `ldaps`               | boolean      | false      | Connect using LDAP over TLS. |
| `verify_ldap_host`    | boolean      | false      | Verify the server certificate during the TLS handshake. |
| `base_dn`             | string       | ou=users,dc=example,dc=org | Base DN the username is appended to. |
| `attribute`           | string       | cn         | RDN attribute the username is bound as. |

### resty.ldap.ldap

Low-level compatibility module used by `resty.ldap` (restored from v0.1.0): `bind_request`, `unbind_request` and `start_tls` over a caller-supplied cosocket. New code should use `resty.ldap.client` instead.
