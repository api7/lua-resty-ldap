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
  verify_ldap_host = false,
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


local _M = {}


function _M.ldap_authenticate(given_username, given_password, conf)
  set_conf_default_values(conf)

  local is_authenticated
  local err, suppressed_err, ok, _

  local sock = tcp()

  sock:settimeout(conf.timeout)

  local opts

  -- keep TLS connections in a separate pool to avoid reusing non-secure
  -- connections and vice-versa, because STARTTLS use the same port
  if conf.start_tls then
    opts = {
      pool = conf.ldap_host .. ":" .. conf.ldap_port .. ":starttls"
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
    _, err = sock:sslhandshake(true, conf.ldap_host, conf.verify_ldap_host)
    if err ~= nil then
      return false, fmt("failed to do SSL handshake with %s:%s: %s",
                        conf.ldap_host, tostring(conf.ldap_port), err)
    end
  end

  local who = conf.attribute .. "=" .. given_username .. "," .. conf.base_dn
  is_authenticated, err = ldap.bind_request(sock, who, given_password)

  ok, suppressed_err = sock:setkeepalive(conf.keepalive)
  if not ok then
    log(ERR, "failed to keepalive to ", conf.ldap_host, ":",
                   tostring(conf.ldap_port), ": ", suppressed_err)
  end

  return is_authenticated, err
end


return _M
