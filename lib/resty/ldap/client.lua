local bunpack  = require "lua_pack".unpack
local ldap     = require "resty.ldap.ldap"
local protocol = require "resty.ldap.protocol"
local asn1     = require "resty.ldap.asn1"

local tostring = tostring
local fmt      = string.format
local log      = ngx.log
local ERR      = ngx.ERR
local tcp      = ngx.socket.tcp

local asn1_parse_ldap_result = asn1.parse_ldap_result


local _M = {}
local mt = { __index = _M }


local function calculate_payload_length(encStr, pos, socket)
    local elen

    pos, elen = bunpack(encStr, "C", pos)

    if elen > 128 then
        elen = elen - 128
        local elenCalc = 0
        local elenNext

        for i = 1, elen do
            elenCalc = elenCalc * 256
            encStr = encStr .. socket:receive(1)
            pos, elenNext = bunpack(encStr, "C", pos)
            elenCalc = elenCalc + elenNext
        end

        elen = elenCalc
    end

    return pos, elen
end

local function _init_socket(self)
    local host = self.host
    local port = self.port
    local socket_config = self.socket_config
    local sock = tcp()

    sock:settimeout(socket_config.socket_timeout)

    -- keep TLS connections in a separate pool to avoid reusing non-secure
    -- connections and vice-versa, because STARTTLS use the same port
    local opts = {}
    if socket_config.start_tls then
        opts = {
            pool = host .. ":" .. port .. ":starttls"
        }
    end

    local ok, err = sock:connect(host, port, opts)
    if not ok then
        log(ERR, "failed to connect to ", host, ":",
            tostring(port), ": ", err)
        return err
    end

    if socket_config.start_tls then
        -- convert connection to a STARTTLS connection only if it is a new connection
        local count, err = sock:getreusedtimes()
        if not count then
            -- connection was closed, just return instead
            return err
        end

        if count == 0 then
            local ok, err = ldap.start_tls(sock)
            if not ok then
                return err
            end
        end
    end

    if socket_config.start_tls or socket_config.ldaps then
        _, err = sock:sslhandshake(true, host, socket_config.ssl_verify)
        if err ~= nil then
            return fmt("failed to do SSL handshake with %s:%s: %s",
                host, tostring(port), err)
        end
    end

    self.socket = sock
end

local function _send(cli, request)
    local bytes, err = cli.socket:send(request)
    if not bytes then
        return err
    end
end

local function _send_recieve(cli, request)
    local err = _send(cli, request)
    if err then
        return nil, err
    end

    local socket = cli.socket
    local len, err = socket:receive(2)
    if not len then
        if err == "timeout" then
            socket:close()
            return nil, err
        end
        return nil, err
    end

    local _, packet_len = calculate_payload_length(len, 2, socket)
    local packet = socket:receive(packet_len)

    local res, err = asn1_parse_ldap_result(packet)
    if err then
        return nil, "Invalid LDAP message encoding: " .. err
    end

    return res
end

function _M.new(_, host, port, client_config)
    if not host or not port then
        return nil, "host and port cannot be nil"
    end

    local opts = client_config or {}
    local socket_config = {
        socket_timeout = opts.socket_timeout or 10000,
        keepalive_timeout = opts.keepalive_timeout or (60 * 1000), -- 10 min
        -- keepalive_size = opts.keepalive_size or 2,
        start_tls = opts.start_tls or false,
        ldaps = opts.ldaps or false,
        ssl_verify = opts.ssl_verify or false,
    }

    local cli = setmetatable({
        host = host,
        port = port,
        socket_config = socket_config,
    }, mt)

    local err = _init_socket(cli)
    if err then
        return nil, err
    end

    return cli
end


function _M.simple_bind(self, dn, password)
    local res, err = _send_recieve(self, protocol.simple_bind_request(dn, password))
    if not res then
        return err
    end

    if res.protocol_op ~= protocol.APP_NO.BindResponse then
        return fmt("Received incorrect Op in packet: %d, expected %d",
            res.protocol_op, protocol.APP_NO.BindResponse)
    end

    if res.result_code ~= 0 then
        local error_msg = protocol.ERROR_MSG[res.result_code]

        return fmt("\n  Error: %s\n  Details: %s",
            error_msg or ("Unknown error occurred (code: " .. res.result_code .. ")"),
            res.diagnostic_msg or "")
    end
end

return _M
