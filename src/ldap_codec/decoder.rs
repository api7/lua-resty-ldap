use mlua::prelude::{Lua, LuaResult, LuaValue};
use bytes::Bytes;
use rasn::der;
use rasn_ldap::{LdapMessage, ProtocolOp};

fn bytes_to_string(b: Bytes) -> Result<String, std::string::FromUtf8Error> {
    return String::from_utf8(b.to_vec());
}

pub fn decode<'lua>(
    lua: &'lua Lua,
    v: LuaValue<'lua>,
) -> LuaResult<(LuaValue<'lua>, LuaValue<'lua>)> {
    let der = match v {
        LuaValue::String(v) => v,
        _ => {
            return Ok((
                LuaValue::Nil,
                LuaValue::String(lua.create_string("wrong format on input data")?),
            ))
        }
    };

    let lm = match der::decode::<LdapMessage>(der.as_bytes()) {
        Ok(lm) => lm,
        Err(err) => {
            let err_str = format!("{}", err.to_string());

            return Ok((
                LuaValue::Nil,
                LuaValue::String(lua.create_string(err_str.as_bytes())?),
            ));
        }
    };

    let result = lua.create_table()?;
    match lm.protocol_op {
        ProtocolOp::BindResponse(resp) => {
            result.set("protocol_op", 1)?;
            result.set("result_code", resp.result_code as i64)?;
            result.set("matched_dn", bytes_to_string(resp.matched_dn).unwrap())?;
            result.set(
                "diagnostic_msg",
                bytes_to_string(resp.diagnostic_message).unwrap(),
            )?;
            return Ok((LuaValue::Table(result), LuaValue::Nil));
        }
        ProtocolOp::SearchResEntry(entry) => {
            result.set("protocol_op", 4)?;
            result.set("entry_dn", bytes_to_string(entry.object_name).unwrap())?;

            let attributes = lua.create_table()?;
            for attribute in entry.attributes.into_iter() {
                let attribute_vals = lua.create_table()?;
                for val in attribute.vals.into_iter() {
                    attribute_vals.push(bytes_to_string(val).unwrap())?
                }
                attributes.set(bytes_to_string(attribute.r#type).unwrap(), attribute_vals)?;
            }

            result.set("attributes", attributes)?;
            return Ok((LuaValue::Table(result), LuaValue::Nil));
        }
        ProtocolOp::SearchResDone(done) => {
            let resp = done.0;
            result.set("protocol_op", 5)?;
            result.set("result_code", resp.result_code as i64)?;
            result.set("matched_dn", bytes_to_string(resp.matched_dn).unwrap())?;
            result.set(
                "diagnostic_msg",
                bytes_to_string(resp.diagnostic_message).unwrap(),
            )?;
            return Ok((LuaValue::Table(result), LuaValue::Nil));
        }
        ProtocolOp::ModifyResponse(resp0) => {
            let resp = resp0.0;
            result.set("protocol_op", 7)?;
            result.set("result_code", resp.result_code as i64)?;
            result.set("matched_dn", bytes_to_string(resp.matched_dn).unwrap())?;
            result.set(
                "diagnostic_msg",
                bytes_to_string(resp.diagnostic_message).unwrap(),
            )?;
            return Ok((LuaValue::Table(result), LuaValue::Nil));
        }
        ProtocolOp::SearchResRef(_) => {
            return Ok((
                LuaValue::Nil,
                LuaValue::String(
                    lua.create_string("decoder not yet implement: search result reference")?,
                ),
            ))
        }
        _ => {
            return Ok((
                LuaValue::Nil,
                LuaValue::String(lua.create_string("decoder not yet implement")?),
            ))
        }
    }
}
