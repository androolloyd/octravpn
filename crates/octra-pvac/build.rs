fn main() {
    let source = std::path::Path::new("../../vendor/octra-pvac");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed=native");
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .opt_level(2)
        .warnings(false)
        .include(source.join("pvac/include"))
        .include(source.join("pvac_ffi"))
        .file("native/bridge.cpp");
    match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => {
            build.flag_if_supported("-march=armv8-a+crypto");
        }
        "x86_64" => {
            build.flag_if_supported("-maes").flag_if_supported("-msse2");
        }
        arch => panic!("PVAC native target unsupported: {arch}"),
    }
    if std::env::var_os("CARGO_FEATURE_BENCHMARK").is_some() {
        build.define("OCTRA_PVAC_BENCHMARK", None);
    }
    build.compile("octra_pvac_native");
}
