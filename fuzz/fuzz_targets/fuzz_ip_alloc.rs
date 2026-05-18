#![no_main]
use libfuzzer_sys::fuzz_target;
use octravpn_mesh::TailnetIpAllocator;

fuzz_target!(|data: &[u8]| {
    // Split the input into (tailnet_id, member_addr, salt_bytes) and
    // run the allocator. Must never panic; the result must always be
    // inside CGNAT /10.
    if data.len() < 4 {
        return;
    }
    let salt = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let rest = &data[4..];
    let split_at = (rest.first().copied().unwrap_or(0) as usize) % rest.len().max(1);
    let (tid_bytes, mem_bytes) = rest.split_at(split_at.min(rest.len()));
    let Ok(tid) = std::str::from_utf8(tid_bytes) else { return };
    let Ok(mem) = std::str::from_utf8(mem_bytes) else { return };

    let alloc = TailnetIpAllocator::with_salt(tid, salt);
    let ip = alloc.allocate(mem);
    let oct = ip.octets();
    // CGNAT /10: 100.64.0.0/10. Assert in fuzz target.
    assert!(oct[0] == 100 && (oct[1] & 0xC0) == 0x40);
});
