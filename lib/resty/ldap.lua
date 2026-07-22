local log = ngx.log
local ERR = ngx.ERR
local ldap = require "resty.ldap.ldap"


local tostring =  tostring
local fmt = string.format
local tcp = ngx.socket.tcp

local default_conf = {
    timeout = 10000,
    start_tls = false,
    ldap_host = "localhost",
    ldap_port = 389,
    ldaps = false,
    base_dn = "ou=users,dc=example,dc=org",
    attribute = "cn",
    keepalive = 60000,
}

local function set_conf_default_values(conf)
    for k, v in pairs(default_conf) do
        if conf[k] == nil then
            conf[k] = v
        end
    end
end


local function resolve_tls_verify(conf)
    if conf.tls_verify ~= nil then
        return conf.tls_verify
    end
    if conf.verify_ldap_host ~= nil then
        return conf.verify_ldap_host
    end
    return false
end


-- RFC 4514 s2.4 escaping for an RDN value; the bind DN below is built from a
-- client-supplied username. Not filter.escape(), which is RFC 4515 and leaves
-- ',' and '+' alone.
local function escape_dn_value(value)
    local lead = value:sub(1, 1)
    -- a lone leading space is covered by the lead rule alone
    local trail = #value > 1 and value:sub(-1) or ""

    local out = value:gsub('([\\",+<>;=])', "\\%1"):gsub("%z", "\\00")

    if trail == " " then
        out = out:sub(1, -2) .. "\\ "
    end
    if lead == " " or lead == "#" then
        out = "\\" .. out
    end

    return out
end


local _M = {}


function _M.ldap_authenticate(given_username, given_password, conf)
    set_conf_default_values(conf)

    -- same coercion contract as ldap.bind_request
    if type(given_username) == "number" then
        given_username = tostring(given_username)
    end
    if type(given_username) ~= "string" then
        return false, "bind username must be a string"
    end

    local is_authenticated
    local err, suppressed_err, ok, _

    local sock = tcp()

    sock:settimeout(conf.timeout)

    local opts

    -- Partition the pool by transport mode and verification policy:
    -- sslhandshake() returns immediately on a reused connection, so a pooled
    -- tls_verify=false connection must never serve one that demands verification.
    local pool_suffix = ""
    if conf.start_tls then
        pool_suffix = ":starttls"
    elseif conf.ldaps then
        pool_suffix = ":ldaps"
    end
    if pool_suffix ~= "" then
        pool_suffix = pool_suffix ..
            (resolve_tls_verify(conf) and ":verify" or ":noverify")
        opts = {
            pool = conf.ldap_host .. ":" .. conf.ldap_port .. pool_suffix
        }
    end

    ok, err = sock:connect(conf.ldap_host, conf.ldap_port, opts)
    if not ok then
        log(ERR, "failed to connect to ", conf.ldap_host, ":",
                 tostring(conf.ldap_port), ": ", err)
        return nil, err
    end

    if conf.start_tls then
        -- convert connection to a STARTTLS connection only if it is a new connection
        local count, err = sock:getreusedtimes()
        if not count then
            -- connection was closed, just return instead
            return nil, err
        end

        if count == 0 then
            local ok, err = ldap.start_tls(sock)
            if not ok then
                return nil, err
            end
        end
    end

    if conf.start_tls or conf.ldaps then
        _, err = sock:sslhandshake(true, conf.ldap_host, resolve_tls_verify(conf))
        if err ~= nil then
            return false, fmt("failed to do SSL handshake with %s:%s: %s",
                              conf.ldap_host, tostring(conf.ldap_port), err)
        end
    end

    local who = conf.attribute .. "=" .. escape_dn_value(given_username) ..
                "," .. conf.base_dn
    is_authenticated, err = ldap.bind_request(sock, who, given_password)

    if is_authenticated == nil then
        -- transport failure; bind_request already closed the socket
        return nil, err
    end

    ok, suppressed_err = sock:setkeepalive(conf.keepalive)
    if not ok then
        log(ERR, "failed to keepalive to ", conf.ldap_host, ":",
                 tostring(conf.ldap_port), ": ", suppressed_err)
    end

    -- who: the canonical escaped bind DN, for callers that key identity on it
    return is_authenticated, err, who
end


return _M
