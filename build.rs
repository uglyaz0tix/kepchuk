use std::env;
use std::path::{Path, PathBuf};

fn main() {
    // set libclang search path on windows if available in mingw
    if env::var("LIBCLANG_PATH").is_err() {
        let mingw_bin = Path::new("C:\\MinGW\\bin");
        if mingw_bin.join("libclang.dll").exists() {
            env::set_var("LIBCLANG_PATH", mingw_bin);
        }
    }

    println!("cargo:rerun-if-changed=csrc/sha256.h");
    println!("cargo:rerun-if-changed=csrc/sha256.c");
    println!("cargo:rerun-if-changed=csrc/hmac.h");
    println!("cargo:rerun-if-changed=csrc/hmac.c");
    println!("cargo:rerun-if-changed=csrc/secure_compare.h");
    println!("cargo:rerun-if-changed=csrc/secure_compare.c");
    println!("cargo:rerun-if-changed=csrc/kep_crypto.h");

    // compile c crypto library
    cc::Build::new()
        .file("csrc/sha256.c")
        .file("csrc/hmac.c")
        .file("csrc/secure_compare.c")
        .include("csrc")
        .flag_if_supported("-std=c11")
        .flag_if_supported("-O3")
        .flag_if_supported("/O2")
        .compile("kep_crypto");

    // generate rust bindings
    let bindings = bindgen::Builder::default()
        .header("csrc/kep_crypto.h")
        .allowlist_function("kep_.*")
        .allowlist_type("kep_.*")
        .allowlist_var("KEP_.*")
        .generate()
        .expect("unable to generate c crypto bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write bindings.rs");
}
