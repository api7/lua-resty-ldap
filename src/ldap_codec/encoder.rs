use mlua::prelude::{Lua, LuaResult, LuaValue};

pub fn encode<'lua>(
    lua: &'lua Lua,
    _: LuaValue<'lua>,
) -> LuaResult<(LuaValue<'lua>, LuaValue<'lua>)> {
    Ok((
        LuaValue::Nil,
        LuaValue::String(lua.create_string("not yet implement")?),
    ))
}
