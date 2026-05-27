use libgssapi::{
    context::{ClientCtx, CtxFlags, SecurityContext},
    credential::{Cred, CredUsage},
    name::Name,
    oid::GSS_NT_HOSTBASED_SERVICE,
};
use mlua::prelude::*;

pub struct GssapiCtx(ClientCtx);

impl LuaUserData for GssapiCtx {
    fn add_methods<'lua, M: LuaUserDataMethods<'lua, Self>>(methods: &mut M) {
        // step(in_token_or_nil) -> out_token_or_nil, is_complete
        methods.add_method_mut("step", |lua, this, in_token: Option<LuaString>| {
            let in_bytes = in_token.map(|s| s.as_bytes().to_vec());
            let in_slice = in_bytes.as_deref();
            match this.0.step(in_slice, None) {
                Err(e) => Err(LuaError::RuntimeError(format!("{}", e))),
                Ok(None) => Ok((LuaValue::Nil, true)),
                Ok(Some(tok)) => {
                    let complete = this.0.is_complete();
                    Ok((LuaValue::String(lua.create_string(&*tok)?), complete))
                }
            }
        });

        // wrap(plaintext) -> wrapped  (integrity only, no encryption — SSF=0)
        methods.add_method_mut("wrap", |lua, this, msg: LuaString| {
            this.0
                .wrap(false, msg.as_bytes())
                .map(|b| lua.create_string(&*b))
                .map_err(|e| LuaError::RuntimeError(format!("{}", e)))
        });

        // unwrap(wrapped) -> plaintext
        methods.add_method_mut("unwrap", |lua, this, msg: LuaString| {
            this.0
                .unwrap(msg.as_bytes())
                .map(|b| lua.create_string(&*b))
                .map_err(|e| LuaError::RuntimeError(format!("{}", e)))
        });
    }
}

// gssapi_new("ldap@hostname") -> GssapiCtx userdata
pub fn new_ctx<'lua>(lua: &'lua Lua, service: LuaString<'lua>) -> LuaResult<LuaAnyUserData<'lua>> {
    let name = Name::new(service.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .map_err(|e| LuaError::RuntimeError(format!("{}", e)))?;
    let cred = Cred::acquire(None, None, CredUsage::Initiate, None)
        .map_err(|e| LuaError::RuntimeError(format!("{}", e)))?;
    let ctx = ClientCtx::new(
        Some(cred),
        name,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
        None,
    );
    lua.create_userdata(GssapiCtx(ctx))
}
