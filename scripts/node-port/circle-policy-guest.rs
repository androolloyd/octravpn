//! A deterministic update with an unused nonpersistent import. Native policy
//! rejects the whole module for updates after activation, even without calling
//! that import. The exported probe prevents the linker from dropping it.
#![no_std]

#[link(wasm_import_module = "octra")]
extern "C" {
    fn host_response_write(pointer: i32, size: i32) -> i32;
    fn host_session_get_len(pointer: i32, size: i32) -> i32;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn octra_alloc(_: i32) -> i32 {
    4096
}

#[no_mangle]
pub extern "C" fn octra_manifest(_: i32, _: i32) -> i32 {
    let manifest = br#"{"methods":[{"name":"update","view":false}]}"#;
    unsafe { host_response_write(manifest.as_ptr() as i32, manifest.len() as i32) };
    0
}

#[no_mangle]
pub extern "C" fn octra_update(_: i32, _: i32) -> i32 {
    let response = b"OCWS1\0\0\0\0\0";
    unsafe { host_response_write(response.as_ptr() as i32, response.len() as i32) };
    0
}

#[no_mangle]
pub extern "C" fn session_probe(pointer: i32, size: i32) -> i32 {
    unsafe { host_session_get_len(pointer, size) }
}
