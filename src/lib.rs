use ldap_codec::{decoder::decode, encoder::encode};
use mlua::prelude::{Lua, LuaResult, LuaTable};

mod ldap_codec;

#[mlua::lua_module]
fn rasn(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;

    exports.set("encode_ldap", lua.create_function(encode)?)?;
    exports.set("decode_ldap", lua.create_function(decode)?)?;

    Ok(exports)
}
