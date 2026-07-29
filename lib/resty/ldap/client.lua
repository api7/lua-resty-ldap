local bunpack  = require("lua_pack").unpack
local protocol = require("resty.ldap.protocol")

local tostring     = tostring
local fmt          = string.format
local tcp          = ngx.socket.tcp
local table_insert = table.insert
local decode_ldap  = protocol.decode_message

-- Upper bound on a single LDAP message body (bytes). A well-formed length such
-- as 84 7f ff ff ff is legal BER but would force a multi-GiB allocation in the
-- worker. 16 MiB comfortably exceeds any real entry.
local MAX_LDAP_MESSAGE_SIZE = 16 * 1024 * 1024

-- fixed BER TLV prefix: identifier octet + initial length octet
local BER_HEADER_LEN = 2


local _M = {}
local mt = { __index = _M }

-- takes the BER_HEADER_LEN-byte header (reading further length octets from the
-- socket as needed); returns body length + header bytes, or nil + error
local function calculate_payload_length(encStr, socket)
    local elen
    local pos = BER_HEADER_LEN -- the initial length octet is the header's last byte

    pos, elen = bunpack(encStr, "C", pos)

    -- 0x80 (indefinite) and 0xff (reserved) are illegal, not short-form lengths
    if elen == 0x80 or elen == 0xff then
        return nil, nil, "invalid BER length: indefinite or reserved form"
    end

    if elen > 128 then
        elen = elen - 128
        local elenCalc = 0
        local elenNext

        for _ = 1, elen do
            elenCalc = elenCalc * 256
            local byte, err = socket:receive(1)
            if not byte then
                return nil, nil, fmt("receive length header failed: %s", err)
            end
            encStr = encStr .. byte
            pos, elenNext = bunpack(encStr, "C", pos)
            elenCalc = elenCalc + elenNext
        end

        elen = elenCalc
    end

    if elen > MAX_LDAP_MESSAGE_SIZE then
        return nil, nil, fmt("ldap message too large: %d bytes", elen)
    end

    return elen, encStr
end

-- every failure path closes sock: _init_socket has not adopted it yet, so
-- nothing else can, and the connection would linger until garbage collection
local function _start_tls(sock)
    -- send STARTTLS request
    local bytes, err = sock:send(protocol.start_tls_request())
    if not bytes then
        sock:close()
        return fmt("send request failed: %s", err)
    end

    -- receive STARTTLS response
    local len, err = sock:receive(BER_HEADER_LEN)
    if not len then
        sock:close()
        return fmt("receive response header failed: %s", err)
    end
    local packet_len, packet_header, lerr = calculate_payload_length(len, sock)
    if not packet_len then
        sock:close()
        return lerr
    end

    local packet, err = sock:receive(packet_len)
    if not packet then
        sock:close()
        return fmt("receive response failed: %s", err)
    end

    local packet = packet_header .. packet
    local res, err = decode_ldap(packet)
    if not res then
        sock:close()
        -- the body can carry DNs and attribute values; keep it out of the error
        return fmt("failed to decode ldap message: %s (%d bytes)",
                   err or "unknown", #packet)
    end

    if res.protocol_op ~= protocol.APP_NO.ExtendedResponse then
        sock:close()
        return fmt("received incorrect op in packet: %d, expected %d",
                    res.protocol_op, protocol.APP_NO.ExtendedResponse)
    end

    if res.result_code ~= 0 then
        local error_msg = protocol.ERROR_MSG[res.result_code]

        sock:close()
        return fmt("error: %s, details: %s",
                    error_msg or ("Unknown error occurred (code: " .. res.result_code .. ")"),
                    res.diagnostic_msg or "")
    end
end

local function _init_socket(self, will_bind)
    local host = self.host
    local port = self.port
    local socket_config = self.socket_config
    local sock = tcp()

    sock:settimeout(socket_config.socket_timeout)

    -- Partition the pool by transport mode and verification policy:
    -- sslhandshake() returns immediately on a reused connection, so a pooled
    -- ssl_verify=false connection must never serve one that demands verification.
    local pool_suffix = ""
    if socket_config.start_tls then
        pool_suffix = ":starttls"
    elseif socket_config.ldaps then
        pool_suffix = ":ldaps"
    end
    if pool_suffix ~= "" then
        pool_suffix = pool_suffix .. (socket_config.ssl_verify and ":verify" or ":noverify")
    end

    -- a connection opened by a Bind pools separately: every drawer binds first,
    -- and that Bind resets the session (RFC 4513 s4), so no identity carries over
    if will_bind then
        pool_suffix = pool_suffix .. ":bind"
    end

    local opts = {
        pool = host .. ":" .. port .. pool_suffix,
        pool_size = socket_config.keepalive_pool_size,
    }

    -- override the value when the user specifies connection pool name,
    -- still partitioned by policy
    if socket_config.keepalive_pool_name and socket_config.keepalive_pool_name ~= "" then
        opts.pool = socket_config.keepalive_pool_name .. pool_suffix
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
            sock:close()
            return fmt("get %s:%s connection re-used time failed: %s",
                        host, tostring(port), err)
        end

        if count == 0 then
            -- STARTTLS (_start_tls closes the socket on every failure)
            local err = _start_tls(sock)
            if err then
                return fmt("launch STARTTLS connection on %s:%s failed: %s",
                            host, tostring(port), err)
            end
        end
    end

    if socket_config.start_tls or socket_config.ldaps then
        local _
        _, err = sock:sslhandshake(true, host, socket_config.ssl_verify)
        if err ~= nil then
            sock:close()
            return fmt("do TLS handshake on %s:%s failed: %s",
                        host, tostring(port), err)
        end
    end

    self.socket = sock
    self.from_bind_pool = will_bind
end

-- drop the socket after an unrecoverable error
local function _reset_socket(cli)
    local sock = cli.socket
    cli.socket = nil
    cli.from_bind_pool = nil
    cli.unpoolable = nil
    if sock then
        sock:close()
    end
end

local function _send_receive(cli, request, multi_resp_hint, will_bind)
    -- opened on first use, held until the caller releases it
    if not cli.socket then
        local err = _init_socket(cli, will_bind)
        if err then
            return nil, fmt("initialize socket failed: %s", err)
        end
    end

    local socket = cli.socket

    -- send req
    local bytes, err = cli.socket:send(request)
    if not bytes then
        _reset_socket(cli)
        return nil, fmt("send request failed: %s", err)
    end

    local result = {}
    -- When the client sends a search request, the server will return several
    -- different entries in a string-like concatenation, so we must use a
    -- loop to complete the bulk extraction of the data.
    -- This does not affect the response of a single "response body".
    while true do
        local len, err = socket:receive(BER_HEADER_LEN)
        if not len then
            -- a search ends at SearchResultDone and a single-response op at its
            -- one message; a timeout or close before either truncates the
            -- exchange, so fail rather than return what arrived so far
            _reset_socket(cli)
            return nil, fmt("receive response failed: %s", err or "unknown")
        end

        local packet_len, packet_header, lerr = calculate_payload_length(len, socket)
        if not packet_len then
            _reset_socket(cli)
            return nil, lerr
        end

        -- Get the data of the specified length
        local packet, err = socket:receive(packet_len)
        if not packet then
            -- When the packet header is read but the packet body cannot be read,
            -- this error is considered unacceptable and therefore an error is
            -- returned directly instead of processing the received data.
            _reset_socket(cli)
            return nil, fmt("receive response failed: %s", err)
        end

        local packet = packet_header .. packet
        local res, err = decode_ldap(packet)
        if not res then
            -- the body can carry DNs and attribute values; keep it out of the error
            _reset_socket(cli)
            return nil, fmt("failed to decode ldap message: %s (%d bytes)",
                            err or "unknown", #packet)
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
        if not multi_resp_hint or
           (res and res.protocol_op == protocol.APP_NO.SearchResultDone) then
            break
        end
    end

    return multi_resp_hint and result or result[1]
end


function _M.new(_, host, port, client_config)
    if not host or not port then
        return nil, "host and port cannot be nil"
    end

    local opts = client_config or {}
    local ssl_verify = opts.ssl_verify
    if ssl_verify == nil then
        ssl_verify = true
    end

    local socket_config = {
        socket_timeout = opts.socket_timeout or 10000,
        keepalive_timeout = opts.keepalive_timeout or (60 * 1000), -- 10 min
        start_tls = opts.start_tls or false,
        ldaps = opts.ldaps or false,
        ssl_verify = ssl_verify,

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


function _M.set_keepalive(self)
    local sock = self.socket
    local unpoolable = self.unpoolable
    self.socket = nil
    self.from_bind_pool = nil
    self.unpoolable = nil
    if not sock then
        return true
    end
    if unpoolable then
        return sock:close()
    end
    return sock:setkeepalive(self.socket_config.keepalive_timeout)
end


function _M.close(self)
    local sock = self.socket
    self.socket = nil
    self.from_bind_pool = nil
    self.unpoolable = nil
    if not sock then
        return true
    end
    return sock:close()
end


function _M.simple_bind(self, dn, password)
    -- as the last argument a (nil, err) return would expand into
    -- _send_receive's multi_resp_hint and send a nil request
    local req, berr = protocol.simple_bind_request(dn, password)
    if not req then
        return false, berr
    end

    -- a bind on a connection drawn from the anonymous pool makes it unpoolable:
    -- set_keepalive would hand its identity to the next anonymous drawer
    if self.socket and not self.from_bind_pool then
        self.unpoolable = true
    end

    local res, err = _send_receive(self, req, nil, true)
    if not res then
        -- transport/decode failure: nil, so callers can tell an unreachable
        -- or broken server (nil) from rejected credentials (false)
        return nil, err
    end

    if res.protocol_op ~= protocol.APP_NO.BindResponse then
        -- the BindResponse may still be queued behind this one: not reusable
        _reset_socket(self)
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
    if not base_dn then
        return false, "base_dn cannot be nil"
    end

    local search_req, err = protocol.search_request(
        base_dn,
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

    local res, err = _send_receive(self, search_req, true) -- mark as potential multi-response operation
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
