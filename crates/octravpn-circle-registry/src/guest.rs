//! WebAssembly guest glue for the existing Circle host ABI.
//! All pointers refer to this guest's linear memory, never native host memory.
use std::cell::RefCell;

use crate::{
    codec, storage_key, OperatorRecord, PublishRequest, EVENT_TOPIC, MAX_RECORD_BYTES,
    MAX_REQUEST_BYTES,
};

#[link(wasm_import_module = "octra")]
extern "C" {
    fn host_response_reset() -> i32;
    fn host_response_write(pointer: i32, length: i32) -> i32;
    fn host_response_finish(status: i32) -> i32;
    fn host_caller_len() -> i32;
    fn host_caller_read(pointer: i32, capacity: i32) -> i32;
    fn host_epoch() -> i64;
    fn host_kv_get_len(key: i32, length: i32) -> i32;
    fn host_kv_get(key: i32, length: i32, output: i32, capacity: i32) -> i32;
    fn host_kv_put(key: i32, length: i32, value: i32, value_length: i32) -> i32;
    fn host_emit_event(topic: i32, topic_length: i32, data: i32, data_length: i32) -> i32;
}

thread_local! { static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; }

#[no_mangle]
pub(crate) extern "C" fn octra_alloc(length: i32) -> i32 {
    if length < 0 || length as usize > MAX_REQUEST_BYTES {
        return -1;
    }
    INPUT.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        buffer.resize(length as usize, 0);
        buffer.as_mut_ptr() as i32
    })
}

fn request(pointer: i32, length: i32) -> Result<Vec<u8>, String> {
    INPUT.with(|buffer| {
        let buffer = buffer.borrow();
        if length < 0 || length as usize != buffer.len() || pointer != buffer.as_ptr() as i32 {
            return Err("request allocation mismatch".into());
        }
        Ok(buffer.clone())
    })
}

fn reply(bytes: &[u8], success: bool) -> i32 {
    // Rust owns the buffers for the full synchronous host call.
    unsafe {
        if host_response_reset() != 0
            || host_response_write(bytes.as_ptr() as i32, bytes.len() as i32) != bytes.len() as i32
            || host_response_finish(i32::from(!success)) != 0
        {
            return 1;
        }
    }
    i32::from(!success)
}

#[no_mangle]
pub(crate) extern "C" fn octra_manifest(_pointer: i32, _length: i32) -> i32 {
    reply(br#"{"schema":"octra_circle_manifest_v1","methods":[{"name":"publish","view":false},{"name":"retire","view":false},{"name":"operator","view":true}]}"#, true)
}

fn caller() -> Result<String, String> {
    let length = unsafe { host_caller_len() };
    if length != 47 {
        return Err("invalid host caller".into());
    }
    let mut bytes = vec![0; length as usize];
    if unsafe { host_caller_read(bytes.as_mut_ptr() as i32, length) } != length {
        return Err("host caller read failed".into());
    }
    String::from_utf8(bytes).map_err(|_| "invalid host caller".into())
}

fn read(operator: &str) -> Result<Option<OperatorRecord>, String> {
    let key = storage_key(operator).map_err(|e| e.to_string())?;
    let length = unsafe { host_kv_get_len(key.as_ptr() as i32, key.len() as i32) };
    if length == -1 {
        return Ok(None);
    }
    if length < 0 || length as usize > MAX_RECORD_BYTES {
        return Err("invalid stored record size".into());
    }
    let mut bytes = vec![0; length as usize];
    if unsafe {
        host_kv_get(
            key.as_ptr() as i32,
            key.len() as i32,
            bytes.as_mut_ptr() as i32,
            length,
        )
    } != length
    {
        return Err("stored record read failed".into());
    }
    let record: OperatorRecord =
        serde_json::from_slice(&bytes).map_err(|_| "invalid stored operator".to_owned())?;
    if record.operator != operator {
        return Err("stored operator identity mismatch".into());
    }
    Ok(Some(record))
}

fn write(record: &OperatorRecord) -> Result<Vec<u8>, String> {
    let key = storage_key(&record.operator).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    if json.len() > MAX_RECORD_BYTES {
        return Err("record exceeds limit".into());
    }
    if unsafe {
        host_kv_put(
            key.as_ptr() as i32,
            key.len() as i32,
            json.as_ptr() as i32,
            json.len() as i32,
        )
    } != 0
    {
        return Err("stored record write failed".into());
    }
    if unsafe {
        host_emit_event(
            EVENT_TOPIC.as_ptr() as i32,
            EVENT_TOPIC.len() as i32,
            json.as_ptr() as i32,
            json.len() as i32,
        )
    } != 0
    {
        return Err("operator event failed".into());
    }
    Ok(json)
}

fn dispatch(bytes: &[u8], view: bool) -> Result<Vec<u8>, String> {
    let req = codec::decode(bytes).map_err(|e| e.to_string())?;
    if view {
        if let ("operator", [codec::Param::String(operator)]) =
            (req.method.as_str(), req.params.as_slice())
        {
            return serde_json::to_vec(&read(operator)?).map_err(|e| e.to_string());
        }
        return Err("unknown view or invalid params".into());
    }
    let caller = caller()?;
    let epoch =
        u64::try_from(unsafe { host_epoch() }).map_err(|_| "invalid host epoch".to_owned())?;
    let previous = read(&caller)?;
    let record = match (req.method.as_str(), req.params.as_slice()) {
        ("publish", [codec::Param::String(json)]) => {
            let req: PublishRequest =
                serde_json::from_str(json).map_err(|_| "invalid publish request".to_owned())?;
            crate::publish(previous.as_ref(), &caller, epoch, req)
        }
        ("retire", [codec::Param::Int(revision)]) => crate::retire(
            previous
                .as_ref()
                .ok_or_else(|| crate::Error::Missing.to_string())?,
            &caller,
            epoch,
            *revision,
        ),
        _ => return Err("unknown update or invalid params".into()),
    }
    .map_err(|e| e.to_string())?;
    write(&record)
}

fn execute(pointer: i32, length: i32, view: bool) -> i32 {
    match request(pointer, length).and_then(|bytes| dispatch(&bytes, view)) {
        Ok(json) => reply(&codec::response(&json), true),
        Err(error) => {
            let json = serde_json::to_vec(&serde_json::json!({"error": error})).unwrap_or_default();
            reply(&codec::response(&json), false)
        }
    }
}

#[no_mangle]
pub(crate) extern "C" fn octra_update(pointer: i32, length: i32) -> i32 {
    execute(pointer, length, false)
}

#[no_mangle]
pub(crate) extern "C" fn octra_query(pointer: i32, length: i32) -> i32 {
    execute(pointer, length, true)
}
