use rust_circle_sdk::{Host, Value};

#[no_mangle]
pub extern "C" fn octra_manifest(_: i32, _: i32) -> i32 {
    Host::respond_manifest_json(r#"{"methods":[{"name":"epoch","view":true}]}"#)
}

#[no_mangle]
pub extern "C" fn octra_query(_: i32, _: i32) -> i32 {
    Host::respond_value(Value::Int(Host::epoch().to_string()))
}

#[no_mangle]
pub extern "C" fn octra_update(_: i32, _: i32) -> i32 { 62 }
