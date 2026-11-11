-- Minimal GSS-API (RFC 2744) client binding over LuaJIT FFI, covering what the
-- SASL GSSAPI mechanism (RFC 4752) needs: establish a Kerberos V5 security
-- context with a host-based service, then wrap/unwrap the security layer
-- negotiation tokens.
--
-- The library is loaded on first use, so requiring this module costs nothing
-- for callers that never bind with GSSAPI.
--
-- Credentials come from the default credential cache of the worker process
-- (KRB5CCNAME, or a client keytab via KRB5_CLIENT_KTNAME). Note that
-- gss_init_sec_context() is a blocking call: with no service ticket cached it
-- contacts the KDC synchronously and stalls the nginx worker meanwhile.

local ffi        = require("ffi")
local bit        = require("bit")

local ffi_new    = ffi.new
local ffi_cast   = ffi.cast
local ffi_gc     = ffi.gc
local ffi_string = ffi.string
local band       = bit.band
local fmt        = string.format
local concat     = table.concat
local type       = type
local pcall      = pcall
local setmetatable = setmetatable


-- Another module may already have declared some of these. LuaJIT accepts an
-- identical typedef or function declaration again, but not a second struct
-- body, so the struct bodies are declared on their own and an existing one is
-- reused once its layout is checked. Any other failure is reported by
-- gssapi_bind instead of breaking require() for callers that never use it.
local cdef_err

local function declare(decl, struct_body)
    if cdef_err then
        return
    end
    local ok, err = pcall(ffi.cdef, decl)
    if not ok and not (struct_body and tostring(err):find("attempt to redefine", 1, true)) then
        cdef_err = "GSS-API FFI declarations failed: " .. tostring(err)
    end
end

-- an existing struct body must match the layout declared here
local function check_layout(name, ref, fields)
    if cdef_err then
        return
    end
    local ok, same = pcall(function()
        local t, r = ffi.typeof(name), ffi.typeof(ref)
        if ffi.sizeof(t) ~= ffi.sizeof(r) then
            return false
        end
        for _, f in ipairs(fields) do
            if ffi.offsetof(t, f) ~= ffi.offsetof(r, f) then
                return false
            end
        end
        return true
    end)
    if not (ok and same) then
        cdef_err = "GSS-API FFI declarations failed: an existing " .. name ..
                   " has a different layout"
    end
end

declare("typedef uint32_t OM_uint32;")

declare("struct gss_OID_desc_struct { OM_uint32 length; void *elements; };", true)
check_layout("struct gss_OID_desc_struct",
             "struct { OM_uint32 length; void *elements; }", { "length", "elements" })
declare("typedef struct gss_OID_desc_struct gss_OID_desc, *gss_OID;")

declare("struct gss_buffer_desc_struct { size_t length; void *value; };", true)
check_layout("struct gss_buffer_desc_struct",
             "struct { size_t length; void *value; }", { "length", "value" })
declare("typedef struct gss_buffer_desc_struct gss_buffer_desc, *gss_buffer_t;")

declare([[
    typedef struct gss_name_struct        *gss_name_t;
    typedef struct gss_ctx_id_struct      *gss_ctx_id_t;
    typedef struct gss_cred_id_struct     *gss_cred_id_t;
    typedef struct gss_channel_bindings_struct *gss_channel_bindings_t;
]])

declare([[
    OM_uint32 gss_import_name(OM_uint32 *minor, gss_buffer_t input_name,
                              gss_OID input_name_type, gss_name_t *output_name);
    OM_uint32 gss_release_name(OM_uint32 *minor, gss_name_t *name);

    OM_uint32 gss_init_sec_context(OM_uint32 *minor, gss_cred_id_t cred,
                                   gss_ctx_id_t *context, gss_name_t target,
                                   gss_OID mech_type, OM_uint32 req_flags,
                                   OM_uint32 time_req,
                                   gss_channel_bindings_t bindings,
                                   gss_buffer_t input_token,
                                   gss_OID *actual_mech_type,
                                   gss_buffer_t output_token,
                                   OM_uint32 *ret_flags, OM_uint32 *time_rec);
    OM_uint32 gss_delete_sec_context(OM_uint32 *minor, gss_ctx_id_t *context,
                                     gss_buffer_t output_token);

    OM_uint32 gss_wrap(OM_uint32 *minor, gss_ctx_id_t context, int conf_req,
                       OM_uint32 qop_req, gss_buffer_t input,
                       int *conf_state, gss_buffer_t output);
    OM_uint32 gss_unwrap(OM_uint32 *minor, gss_ctx_id_t context,
                         gss_buffer_t input, gss_buffer_t output,
                         int *conf_state, OM_uint32 *qop_state);

    OM_uint32 gss_release_buffer(OM_uint32 *minor, gss_buffer_t buffer);
    OM_uint32 gss_display_status(OM_uint32 *minor, OM_uint32 status_value,
                                 int status_type, gss_OID mech_type,
                                 OM_uint32 *message_context,
                                 gss_buffer_t status_string);
]])


local GSS_S_COMPLETE        = 0
local GSS_S_CONTINUE_NEEDED = 1
local GSS_C_GSS_CODE        = 1
local GSS_C_MECH_CODE       = 2
local GSS_C_MUTUAL_FLAG     = 2
local GSS_C_SEQUENCE_FLAG   = 8
local GSS_C_INTEG_FLAG      = 32
local GSS_C_QOP_DEFAULT     = 0

-- RFC 2744 s3.9.1: the calling-error and routine-error fields
local function gss_error(major)
    return band(major, 0xffff0000) ~= 0
end

-- RFC 4752 s3.1 only defines how to proceed on these, so any other status
-- fails the exchange, including a supplementary bit such as GSS_S_GAP_TOKEN
-- or GSS_S_DUPLICATE_TOKEN on an otherwise successful call
local function gss_ok(major, continue_ok)
    return major == GSS_S_COMPLETE
        or (continue_ok and major == GSS_S_CONTINUE_NEEDED)
end


-- OIDs are built here instead of referencing the libraries' exported
-- variables, whose names differ between MIT and Heimdal.
local OID_BYTES = {
    -- 1.2.840.113554.1.2.1.4 GSS_C_NT_HOSTBASED_SERVICE (RFC 2743 s4.1)
    hostbased_service = "\42\134\72\134\247\18\1\2\1\4",
    -- 1.2.840.113554.1.2.2 Kerberos V5 (RFC 1964), the only mechanism the SASL
    -- GSSAPI mechanism may use (RFC 4752 s1)
    krb5 = "\42\134\72\134\247\18\1\2\2",
}

local function make_oid(bytes)
    local oid = ffi_new("gss_OID_desc")
    oid.length = #bytes
    oid.elements = ffi_cast("void *", bytes)
    return oid
end

-- created with the library, once the declarations are known to be usable
local NT_HOSTBASED_SERVICE, MECH_KRB5


local _M = {
    -- anchor the OID bytes for the module's lifetime: the gss_OID_desc structs
    -- hold raw pointers into these strings, invisible to the garbage collector
    _oid_bytes = OID_BYTES,
}

-- sonames tried in order; MIT first, as Kerberos SASL deployments mostly use it
_M.library_names = {
    "gssapi_krb5",
    "libgssapi_krb5.so.2",
    "libgssapi.so.3",
}

local lib

-- shared scratch for the minor status out-parameter; every call reads it
-- immediately, and LuaJIT FFI calls do not yield
local minorp

local function load_library()
    if lib then
        return lib
    end
    if cdef_err then
        return nil, cdef_err
    end

    NT_HOSTBASED_SERVICE = NT_HOSTBASED_SERVICE or make_oid(OID_BYTES.hostbased_service)
    MECH_KRB5            = MECH_KRB5 or make_oid(OID_BYTES.krb5)
    minorp               = minorp or ffi_new("OM_uint32[1]")

    local errs = {}
    for _, name in ipairs(_M.library_names) do
        local ok, l = pcall(ffi.load, name)
        if ok then
            lib = l
            return lib
        end
        errs[#errs + 1] = l
    end

    return nil, "failed to load the GSS-API library: " .. concat(errs, "; ")
end


local function status_messages(out, status, status_type, mech)
    local msg_ctx = ffi_new("OM_uint32[1]", 0)
    local buf = ffi_new("gss_buffer_desc")
    local dminor = ffi_new("OM_uint32[1]")
    -- the loop is bounded in case a library never clears msg_ctx
    for _ = 1, 8 do
        local major = lib.gss_display_status(dminor, status, status_type, mech,
                                             msg_ctx, buf)
        if gss_error(major) then
            break
        end
        if buf.length > 0 then
            out[#out + 1] = ffi_string(buf.value, buf.length)
        end
        lib.gss_release_buffer(dminor, buf)
        if msg_ctx[0] == 0 then
            break
        end
    end
end

-- render a major/minor status pair as text, e.g. "Unspecified GSS failure.
-- Minor code may provide more information: No Kerberos credentials available"
local function gss_strerror(what, major, minor)
    local msgs = {}
    status_messages(msgs, major, GSS_C_GSS_CODE, nil)
    if minor ~= 0 then
        status_messages(msgs, minor, GSS_C_MECH_CODE, MECH_KRB5)
    end
    if #msgs == 0 then
        return fmt("%s failed (major 0x%08x, minor %d)", what, major, minor)
    end
    return fmt("%s failed: %s", what, concat(msgs, ": "))
end


local function free_name(namep)
    if namep[0] ~= nil then
        lib.gss_release_name(ffi_new("OM_uint32[1]"), namep)
    end
end

local function free_ctx(ctxp)
    if ctxp[0] ~= nil then
        lib.gss_delete_sec_context(ffi_new("OM_uint32[1]"), ctxp, nil)
    end
end

-- A gss_buffer_desc only holds a raw pointer into its Lua string, which does
-- not keep the string alive, and a local that is not used again after the
-- call may no longer reference it in JIT-compiled code. Input strings are
-- therefore pinned here until the native call that reads them has returned
-- (unpin()). One slot is enough: each call takes a single input buffer, and
-- nothing yields between filling the buffer and the call.
local pinned = {} -- luacheck: ignore 241

local function unpin()
    pinned[1] = nil
end

-- fill a gss_buffer_desc from a Lua string, pinned until unpin()
local function input_buffer(s)
    pinned[1] = s
    local buf = ffi_new("gss_buffer_desc")
    buf.length = #s
    buf.value = ffi_cast("void *", s)
    return buf
end

-- copy a library-allocated buffer into a Lua string and release it
local function take_buffer(buf)
    local s = buf.length > 0 and ffi_string(buf.value, buf.length) or ""
    lib.gss_release_buffer(minorp, buf)
    return s
end


local ctx_mt = {}
ctx_mt.__index = ctx_mt

-- Feed the server's token (nil on the first call) into the context.
-- Returns token, complete: the token to send to the server ("" when there is
-- none), and whether the context is now established. Returns nil, err on
-- failure.
function ctx_mt.step(self, in_token)
    if self.complete then
        return nil, "GSS-API context already established"
    end
    if self.ctxp[0] == nil and in_token ~= nil then
        return nil, "the first GSS-API step takes no input token"
    end
    if in_token ~= nil and type(in_token) ~= "string" then
        return nil, "input token must be a string"
    end

    local in_buf = in_token and input_buffer(in_token) or nil
    local out_buf = ffi_new("gss_buffer_desc")
    local ret_flags = ffi_new("OM_uint32[1]")

    local major = lib.gss_init_sec_context(minorp, nil, self.ctxp,
                                           self.namep[0], MECH_KRB5,
                                           -- integrity: RFC 4752 s3.1
                                           GSS_C_MUTUAL_FLAG + GSS_C_SEQUENCE_FLAG
                                               + GSS_C_INTEG_FLAG,
                                           0, nil, in_buf, nil, out_buf,
                                           ret_flags, nil)
    unpin()
    local minor = minorp[0]
    local token = take_buffer(out_buf)

    if not gss_ok(major, true) then
        return nil, gss_strerror("gss_init_sec_context", major, minor)
    end

    if major == GSS_S_CONTINUE_NEEDED then
        return token, false
    end

    -- the server must have proven its identity, or the bind is not to the
    -- server named by the service principal
    if band(ret_flags[0], GSS_C_MUTUAL_FLAG) == 0 then
        return nil, "GSS-API context established without mutual authentication"
    end
    -- the security layer negotiation tokens must be integrity protected
    if band(ret_flags[0], GSS_C_INTEG_FLAG) == 0 then
        return nil, "GSS-API context established without integrity protection"
    end

    self.complete = true
    return token, true
end

-- integrity-protect msg (no confidentiality, as RFC 4752 s3.1 requires for the
-- security layer negotiation); returns the wrapped token, or nil, err
function ctx_mt.wrap(self, msg)
    if not self.complete then
        return nil, "GSS-API context not established"
    end
    if type(msg) ~= "string" then
        return nil, "message must be a string"
    end

    local in_buf = input_buffer(msg)
    local out_buf = ffi_new("gss_buffer_desc")
    local major = lib.gss_wrap(minorp, self.ctxp[0], 0, GSS_C_QOP_DEFAULT,
                               in_buf, nil, out_buf)
    unpin()
    local minor = minorp[0]
    local wrapped = take_buffer(out_buf)
    if not gss_ok(major) then
        return nil, gss_strerror("gss_wrap", major, minor)
    end
    return wrapped
end

-- verify and strip the protection on a token from the server; returns the
-- plaintext, or nil, err
function ctx_mt.unwrap(self, token)
    if not self.complete then
        return nil, "GSS-API context not established"
    end
    if type(token) ~= "string" then
        return nil, "token must be a string"
    end

    local in_buf = input_buffer(token)
    local out_buf = ffi_new("gss_buffer_desc")
    local major = lib.gss_unwrap(minorp, self.ctxp[0], in_buf, out_buf, nil, nil)
    unpin()
    local minor = minorp[0]
    local plain = take_buffer(out_buf)
    if not gss_ok(major) then
        return nil, gss_strerror("gss_unwrap", major, minor)
    end
    return plain
end

-- release the context and target name now instead of at garbage collection
function ctx_mt.free(self)
    free_ctx(self.ctxp)
    free_name(self.namep)
end


-- Create a client context for a host-based service name such as
-- "ldap@ldap.example.com". Returns the context, or nil, err.
function _M.new(service_name)
    if type(service_name) ~= "string" or service_name == "" then
        return nil, "service name must be a non-empty string"
    end

    local _, err = load_library()
    if err then
        return nil, err
    end

    local namep = ffi_gc(ffi_new("gss_name_t[1]"), free_name)
    local name_buf = input_buffer(service_name)
    local major = lib.gss_import_name(minorp, name_buf, NT_HOSTBASED_SERVICE, namep)
    unpin()
    if not gss_ok(major) then
        return nil, gss_strerror("gss_import_name", major, minorp[0])
    end

    return setmetatable({
        namep    = namep,
        ctxp     = ffi_gc(ffi_new("gss_ctx_id_t[1]"), free_ctx),
        complete = false,
    }, ctx_mt)
end


return _M
