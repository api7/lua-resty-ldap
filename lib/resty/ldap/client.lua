local bunpack  = require("lua_pack").unpack
local protocol = require("resty.ldap.protocol")
local to_hex   = require("resty.string").to_hex
local ok, rasn = pcall(require, "rasn")

if not ok then
    error("failed to load rasn library: " .. rasn)
end

local tostring     = tostring
local fmt          = string.format
local tcp          = ngx.socket.tcp
local table_insert = table.insert
local string_char  = string.char
local rasn_decode  = rasn.decode_ldap


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

    return pos, elen, encStr
end

local function _start_tls(sock)
    -- send STARTTLS request
    local bytes, err = sock:send(protocol.start_tls_request())
    if not bytes then
        return fmt("send request failed: %s", err)
    end

    -- receive STARTTLS response
    local len, err = sock:receive(2)
    if not len then
        if err == "timeout" then
            sock:close()
        end
        return fmt("receive response header failed: %s", err)
    end
    local _, packet_len, packet_header = calculate_payload_length(len, 2, sock)

    local packet, err = sock:receive(packet_len)
    if not packet then
        sock:close()
        return fmt("receive response failed: %s", err)
    end

    local packet = packet_header .. packet
    local ok, res, err = pcall(rasn_decode, packet)
    if not ok or err then
        return nil, fmt(
            "failed to decode ldap message: %s, message: %s",
            not ok and res or err, -- error returned in second value by pcall
            to_hex(packet)
        )
    end

    if res.protocol_op ~= protocol.APP_NO.ExtendedResponse then
        return fmt("received incorrect op in packet: %d, expected %d",
                    res.protocol_op, protocol.APP_NO.ExtendedResponse)
    end

    if res.result_code ~= 0 then
        local error_msg = protocol.ERROR_MSG[res.result_code]

        return fmt("error: %s, details: %s",
                    error_msg or ("Unknown error occurred (code: " .. res.result_code .. ")"),
                    res.diagnostic_msg or "")
    end
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
        pool_size = socket_config.keepalive_pool_size,
    }

    -- override the value when the user specifies connection pool name
    if socket_config.keepalive_pool_name and socket_config.keepalive_pool_name ~= "" then
        opts.pool = socket_config.keepalive_pool_name
    end

    local ok, err = sock:connect(host, port, opts)
    if not ok then
        return fmt("connect to %s:%s failed: %s", host, tostring(port), err)
    end

    if socket_config.start_tls then
        -- convert connection to a STARTTLS connection only if it is a new connection
        local count, err = sock:getreusedtimes()
        if not count then
            -- connection was closed, just return instead
            return fmt("get %s:%s connection re-used time failed: %s",
                        host, tostring(port), err)
        end

        if count == 0 then
            -- STARTTLS
            local err = _start_tls(sock)
            if err then
                return fmt("launch STARTTLS connection on %s:%s failed: %s",
                            host, tostring(port), err)
            end
        end
    end

    if socket_config.start_tls or socket_config.ldaps then
        _, err = sock:sslhandshake(true, host, socket_config.ssl_verify)
        if err ~= nil then
            return fmt("do TLS handshake on %s:%s failed: %s",
                        host, tostring(port), err)
        end
    end

    self.socket = sock
end

local function _send_recieve(cli, request, multi_resp_hint)
    -- initialize socket
    local err = _init_socket(cli)
    if err then
        return nil, fmt("initialize socket failed: %s", err)
    end

    local socket = cli.socket

    -- send req
    local bytes, err = cli.socket:send(request)
    if not bytes then
        return nil, fmt("send request failed: %s", err)
    end

    -- Each response in a multi-response body has ASCII NULL(0x00) as its ending,
    -- so here the reader is created using receiveuntil.
    local reader = socket:receiveuntil(string_char(0x00))

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
                return nil, fmt("receive response failed: %s", err)
            end
            break -- read done, data has been taken to the end
        end
        local _, packet_len, packet_header = calculate_payload_length(len, 2, socket)

        -- Get the data of the specified length
        local packet, err = socket:receive(packet_len)
        if not packet then
            -- When the packet header is read but the packet body cannot be read,
            -- this error is considered unacceptable and therefore an error is
            -- returned directly instead of processing the received data.
            socket:close()
            return nil, err
        end

        local packet = packet_header .. packet
        local ok, res, err = pcall(rasn_decode, packet)
        if not ok or err then
            return nil, fmt(
                "failed to decode ldap message: %s, message: %s",
                not ok and res or err, -- error returned in second value by pcall
                to_hex(packet)
            )
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
        keepalive_pool_name = opts.keepalive_pool_name or nil,
        keepalive_pool_size = opts.keepalive_pool_size or 2,
    }

    local cli = setmetatable({
        host = host,
        port = port,
        socket_config = socket_config,
    }, mt)

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


        return false, fmt("simple bind failed, error: %s, details: %s",
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
        filter        or "(objectClass=*)", -- filter
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
        end
    end

    return res
end


return _M
