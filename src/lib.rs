use codec::{decoder::decode, encoder::encode};
use mlua::prelude::{Lua, LuaResult, LuaTable};

mod codec;

#[mlua::lua_module]
fn rasn(lua: &Lua) -> LuaResult<LuaTable> {
    let exports = lua.create_table()?;

    exports.set("encode", lua.create_function(encode)?)?;
    exports.set("decode", lua.create_function(decode)?)?;

    Ok(exports)
}
