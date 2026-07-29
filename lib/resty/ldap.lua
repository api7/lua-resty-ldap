local log = ngx.log
local ERR = ngx.ERR
local client = require "resty.ldap.client"


local tostring = tostring

local default_conf = {
    timeout = 10000,
    start_tls = false,
    ldap_port = 389,
    ldaps = false,
    tls_verify = true,
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

    if conf.ldap_host == nil or conf.ldap_host == "" then
        return nil, "ldap_host is required"
    end
    if conf.base_dn == nil or conf.base_dn == "" then
        return nil, "base_dn is required"
    end

    -- same coercion contract as protocol.simple_bind_request
    if type(given_username) == "number" then
        given_username = tostring(given_username)
    end
    if type(given_username) ~= "string" then
        return false, "bind username must be a string"
    end

    -- RFC 4513 s5.1.2: a non-empty DN with an empty password is an
    -- unauthenticated bind, which some servers accept as an anonymous
    -- success -- an authentication bypass, so it must never reach the wire.
    -- Other invalid types are rejected by protocol.simple_bind_request.
    if given_password == nil or given_password == "" then
        return false, "bind password is missing or empty"
    end

    local cli = client:new(conf.ldap_host, conf.ldap_port, {
        socket_timeout    = conf.timeout,
        keepalive_timeout = conf.keepalive,
        start_tls         = conf.start_tls,
        ldaps             = conf.ldaps,
        ssl_verify        = conf.tls_verify,
    })

    local who = conf.attribute .. "=" .. escape_dn_value(given_username) ..
                "," .. conf.base_dn
    local is_authenticated, bind_err = cli:simple_bind(who, given_password)

    -- pooled even when the bind was rejected: a failed bind leaves the
    -- session anonymous (RFC 4513 s4), and the next call rebinds anyway
    local released, release_err = cli:set_keepalive()
    if not released then
        log(ERR, "failed to return the connection to the pool: ", release_err)
    end

    if is_authenticated == nil then
        -- connect, TLS or transport failure; the client already dropped the socket
        log(ERR, "failed to bind to ", conf.ldap_host, ":",
                 tostring(conf.ldap_port), ": ", bind_err)
        return nil, bind_err
    end

    -- who: the canonical escaped bind DN, for callers that key identity on it
    return is_authenticated, bind_err, who
end


return _M
