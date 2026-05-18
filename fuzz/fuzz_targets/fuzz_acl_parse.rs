#![no_main]
use libfuzzer_sys::fuzz_target;
use octravpn_mesh::AclDoc;

fuzz_target!(|data: &[u8]| {
    // Parse arbitrary bytes as TOML → AclDoc. Must never panic; an
    // Err is fine.
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = AclDoc::from_toml(s);
});
