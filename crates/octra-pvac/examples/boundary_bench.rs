//! Measure Rust ownership/C ABI cost against a C++ loop over the same calls.
use std::{hint::black_box, time::Instant};

fn main() {
    // Public deterministic fixtures only; no wallet secrets enter benchmark output.
    let (pk, sk) = octra_pvac::keygen(&[17; 32]).unwrap();
    let cipher = pk.encrypt(&sk, 123, &[29; 32]).unwrap();
    let iterations = 2000_u32;
    let mut native = Vec::new();
    let mut rust = Vec::new();
    for index in 0..9 {
        let measure_native = || pk.reference_add_ns(&cipher, iterations as usize).unwrap();
        let measure_rust = || {
            let start = Instant::now();
            for _ in 0..iterations {
                black_box(pk.add(&cipher, &cipher).unwrap());
            }
            start.elapsed().as_secs_f64() * 1_000_000_000.0
        };
        let (a, b) = if index % 2 == 0 {
            (measure_native(), measure_rust())
        } else {
            let b = measure_rust();
            (measure_native(), b)
        };
        native.push(a / f64::from(iterations));
        rust.push(b / f64::from(iterations));
    }
    native.sort_by(f64::total_cmp);
    rust.sort_by(f64::total_cmp);
    println!("{{\"scope\":\"cached key/cipher add and release; no serialization or worker IPC\",\"iterations_per_sample\":{iterations},\"samples\":9,\"native_median_ns\":{},\"rust_median_ns\":{},\"rust_over_native\":{},\"native_samples_ns\":{:?},\"rust_samples_ns\":{:?}}}", native[4], rust[4], rust[4]/native[4], native, rust);
}
