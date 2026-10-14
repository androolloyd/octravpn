//! Commit-effect qualification guest using the pinned, unmodified native SDK.
use rust_circle_sdk::{decode_request, Host, Request, Value};
fn optional(v:&Value)->Option<&str> {if let Value::String(s)=v {Some(s)} else {None}}
fn target(value:&str)->Result<String,i32> {if value=="self" {Host::self_addr()} else {Ok(value.into())}}
fn public(p:&[Value], override_target:Option<&str>)->Result<(),i32> {
    let t=target(override_target.unwrap_or(p[0].as_string().ok_or(70)?))?;
    Host::circle_asset_put(&t,p[1].as_string().ok_or(71)?,p[2].as_string().ok_or(72)?,p[3].as_string().ok_or(73)?,optional(&p[4]))?;Ok(())
}
fn encrypted(p:&[Value], override_target:Option<&str>)->Result<(),i32> {
    let t=target(override_target.unwrap_or(p[0].as_string().ok_or(70)?))?;
    Host::circle_asset_put_encrypted_at(&t,p[1].as_string().ok_or(71)?,p[2].as_string().ok_or(72)?,p[3].as_string().ok_or(73)?,p[4].as_string().ok_or(74)?,p[5].as_string().ok_or(75)?,p[6].as_string().ok_or(76)?,optional(&p[7]),optional(&p[8]),optional(&p[9]),optional(&p[10]),optional(&p[11]))?;Ok(())
}
fn run(r:&Request)->Result<Value,i32> {
    Host::kv_put_string("effect_method",&r.method)?;
    Host::emit_event("Enter",r.method.as_bytes())?;
    match r.method.as_str() {
        "assets"|"fail"=>{for p in r.params.chunks_exact(5) {public(p,None)?;}if r.method=="fail" {return Err(77);}},
        "encrypted"=>{for p in r.params.chunks_exact(12) {encrypted(p,None)?;}},
        "spawn"|"spawn_assets"|"spawn_encrypted"|"spawn_call"=>{
            for _ in 0..r.int_param(2)? {
                let child=Host::circle_spawn(r.string_param(0)?,r.string_param(1)?)?;
                Host::emit_event("Child",child.as_bytes())?;
                Host::kv_put_string("child",&child)?;
                if r.method=="spawn_assets" {for p in r.params[3..].chunks_exact(5) {public(p,Some(&child))?;}}
                if r.method=="spawn_encrypted" {for p in r.params[3..].chunks_exact(12) {encrypted(p,Some(&child))?;}}
                if r.method=="spawn_call" {Host::call(&child,"assets",&[])?;}
            }
        },
        "chain"|"after_fail"=>{
            Host::call(r.string_param(0)?,r.string_param(1)?,&r.params[2..])?;
            if r.method=="after_fail" {return Err(78);}
        },
        _=>return Err(99),
    }
    Host::emit_event("Exit",r.method.as_bytes())?;
    Ok(Value::Bool(true))
}
#[no_mangle]
pub extern "C" fn octra_manifest(_:i32,_:i32)->i32 {
    Host::respond_manifest_json(r#"{"methods":[{"name":"assets","view":false},{"name":"encrypted","view":false},{"name":"spawn","view":false},{"name":"spawn_assets","view":false},{"name":"spawn_encrypted","view":false},{"name":"spawn_call","view":false},{"name":"fail","view":false},{"name":"chain","view":false},{"name":"after_fail","view":false}]}"#)
}
#[no_mangle]
pub extern "C" fn octra_update(pointer:i32,length:i32)->i32 {
    match decode_request(pointer,length).and_then(|r|run(&r)) {Ok(v)=>Host::respond_value(v),Err(e)=>e}
}
