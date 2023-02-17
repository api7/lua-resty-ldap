local bunpack  = require "lua_pack".unpack
local ldap     = require "resty.ldap.ldap"
local protocol = require "resty.ldap.protocol"
local asn1     = require "resty.ldap.asn1"
local resty_string = require("resty.string")

local tostring     = tostring
local fmt          = string.format
local log          = ngx.log
local ERR          = ngx.ERR
local DEBUG        = ngx.DEBUG
local tcp          = ngx.socket.tcp
local table_insert = table.insert

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
    local opts = {
        pool = host .. ":" .. port .. (socket_config.start_tls and ":starttls" or ""),
        pool_size = socket_config.pool_size,
    }

    -- override the value when the user specifies connection pool name
    if socket_config.pool_name and socket_config.pool_name ~= "" then
        opts.pool = socket_config.pool_name
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

local function _send_recieve(cli, request, multi_resp_hint)
    local err = _send(cli, request)
    if err then
        return nil, err
    end

    local socket = cli.socket

    -- Each response in a multi-response body has ASCII NULL(0x00) as its ending,
    -- so here the reader is created using receiveuntil.
    local reader = socket:receiveuntil(string.char(0x00))

    local result = {}
    -- When the client sends a search request, the server will return several
    -- different entries in a string-like concatenation, sto we must use a
    -- loop to complete the bulk extraction of the data.
    -- This does not affect the response of a single "response body".
    while true do
        -- Takes the packet header of a single request body, which has a length
        -- of two bytes, where the second byte is the length of this response
        -- body packet.
        local len, err = reader(2)
        if not len then
            if err == "timeout" then
                socket:close()
                return nil, err
            end
            break -- read done, data has been taken to the end
        end
        local _, packet_len = calculate_payload_length(len, 2, socket)

        -- Get the data of the specified length
        local packet, err = socket:receive(packet_len)
        if not packet then
            -- When the packet header is read but the packet body cannot be read,
            -- this error is considered unacceptable and therefore an error is
            -- returned directly instead of processing the received data.
            socket:close()
            return nil, err
        end
        local res, err = asn1_parse_ldap_result(packet)
        if err then
            return nil, fmt("invalid ldap message encoding: %s, message: %s", err, resty_string.to_hex(packet))
        end
        table_insert(result, res)

        -- This is an ugly patch to actively stop continuous reading. When a search
        -- request ends, the last result will be SearchResultDone, at which point
        -- the continuous reading stops.
        -- The deeper reason is that the LDAP protocol does not provide a global
        -- field that specifies the total length of this protocol packet, it is
        -- just a straight stack of LDAP messages. Therefore the parser implementor
        -- does not know exactly how many bytes of data should be fetched, and has
        -- to read in greedy mode.
        -- The socket read timeout will be used as a fallback when an exception is
        -- encountered and this does not end the loop.
        if not multi_resp_hint or
           (res and res.protocol_op == protocol.APP_NO.SearchResultDone) then
            break
        end
    end

    -- put back into the connection pool
    socket:setkeepalive(cli.socket_config.keepalive_timeout)

    return multi_resp_hint and result or result[1]
end


function _M.new(_, host, port, client_config)
    if not host or not port then
        return nil, "host and port cannot be nil"
    end

    local opts = client_config or {}
    local socket_config = {
        socket_timeout = opts.socket_timeout or 10000,
        keepalive_timeout = opts.keepalive_timeout or (60 * 1000), -- 10 min
        start_tls = opts.start_tls or false,
        ldaps = opts.ldaps or false,
        ssl_verify = opts.ssl_verify or false,

        -- Specify the connection pool name directly to ensure that connections
        -- with the same connection parameters but using different authentication
        -- methods are not put into the same pool.
        pool_name = opts.pool_name or nil,
        pool_size = opts.pool_size or 2,
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
        return false, err
    end

    if res.protocol_op ~= protocol.APP_NO.BindResponse then
        return false, fmt("Received incorrect Op in packet: %d, expected %d",
            res.protocol_op, protocol.APP_NO.BindResponse)
    end

    if res.result_code ~= 0 then
        local error_msg = protocol.ERROR_MSG[res.result_code]

        return false, fmt("\n  Error: %s\n  Details: %s",
            error_msg or ("Unknown error occurred (code: " .. res.result_code .. ")"),
            res.diagnostic_msg or "")
    end

    return true
end


function _M.search(self, base_dn, scope, deref_aliases, size_limit, time_limit,
                   types_only, filter, attributes)
    local search_req, err = protocol.search_request(
        base_dn       or 'dc=example,dc=org',
        scope         or protocol.SEARCH_SCOPE_WHOLE_SUBTREE,
        deref_aliases or protocol.SEARCH_DEREF_ALIASES_ALWAYS,
        size_limit    or 0, -- size limit
        time_limit    or 0, -- time limit
        types_only    or false, -- type only
        filter        or "(objectClass=posixAccount)", -- filter
        attributes    or {"objectClass"} -- attr
    )
    if not search_req then
        return false, err
    end

    local res, err = _send_recieve(self, search_req, true) -- mark as potential multi-response operation
    if not res then
        return false, err
    end

    for index, item in ipairs(res) do
        if item.protocol_op == protocol.APP_NO.SearchResultDone then
            if item.result_code ~= 0 then
                local error_msg = protocol.ERROR_MSG[item.result_code]
                return false, fmt(
                    "search failed, error: %s, details: %s",
                    error_msg or ("Unknown error occurred (code: " .. item.result_code .. ")"),
                    item.diagnostic_msg or "")
            end
            res[index] = nil
        else
            res[index] = item.search_entries
        end
    end

    return res
end


return _M
