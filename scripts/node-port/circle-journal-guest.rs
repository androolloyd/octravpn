//! Purpose-built native journal qualification using the unmodified upstream SDK.
use rust_circle_sdk::{decode_request, Host, Request, Value};
fn visits() -> Result<i64,i32> {
    let n=Host::kv_get_string("visits")?.unwrap_or_else(||"0".into()).parse::<i64>().map_err(|_|60)?+1;
    Host::kv_put_string("visits",&n.to_string())?;Ok(n)
}
fn run(r:&Request)->Result<Option<Value>,i32> {
    let n=visits()?;
    Host::emit_event("Enter",format!("{}:{n}",r.method).as_bytes())?;
    let value=match r.method.as_str() {
        "money"|"fail"=>{
            let value=Host::call_value()?;let balance=Host::balance()?;
            Host::kv_put_string("value",value.as_string().ok_or(61)?)?;
            Host::kv_put_string("balance",balance.as_string().ok_or(62)?)?;
            let ok=Host::transfer(r.string_param(0)?,r.string_param(1)?)?;
            Host::kv_put_string("after_balance",Host::balance()?.as_string().ok_or(63)?)?;
            if r.method=="fail" {return Err(77);}
            Some(Value::Bool(ok))
        },
        "chain"|"after_fail"|"twice"=>{
            let result=Host::call(r.string_param(0)?,r.string_param(1)?,&r.params[2..])?;
            if r.method=="twice" {Host::call(r.string_param(0)?,r.string_param(1)?,&r.params[2..])?;}
            Host::kv_put_string("after_visits",&Host::kv_get_string("visits")?.ok_or(64)?)?;
            if r.method=="after_fail" {return Err(78);}
            Some(result)
        },
        "recurse"=>{
            let n=r.int_param(0)?;
            Some(if n>0 {Host::call(r.string_param(1)?,"recurse",&[Value::Int((n-1).to_string()),r.params[1].clone()])?} else {Value::Int("42".into())})
        },
        "events"=>{
            for i in 0..r.int_param(0)? {Host::emit_event("Loop",i.to_string().as_bytes())?;}
            Some(Value::Bool(true))
        },
        "many"=>{
            for _ in 0..4 {Host::call(r.string_param(0)?,"events",&r.params[1..])?;}
            Some(Value::Bool(true))
        },
        "reserved"=>{
            Host::kv_put_string("balance_cell:bad:ciphertext_commitment","bad")?;
            Some(Host::call_value()?)
        },
        "return"=>Some(r.param(0).cloned().unwrap_or(Value::Null)),
        "empty"=>None,
        _=>return Err(99),
    };
    Host::emit_event("Exit",r.method.as_bytes())?;
    Ok(value)
}
#[no_mangle]
pub extern "C" fn octra_manifest(_:i32,_:i32)->i32 {
    Host::respond_manifest_json(r#"{"methods":[{"name":"money","view":false},{"name":"fail","view":false},{"name":"chain","view":false},{"name":"after_fail","view":false},{"name":"twice","view":false},{"name":"recurse","view":false},{"name":"events","view":false},{"name":"many","view":false},{"name":"reserved","view":false},{"name":"return","view":false},{"name":"empty","view":false}]}"#)
}
#[no_mangle]
pub extern "C" fn octra_update(pointer:i32,length:i32)->i32 {
    match decode_request(pointer,length).and_then(|r|run(&r)) {
        Ok(Some(v))=>Host::respond_value(v),Ok(None)=>0,Err(code)=>code,
    }
}
