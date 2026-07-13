// Report: "LaZer Integration Feasibility".

use std::{env, path::PathBuf};

fn required_dir(name: &str) -> PathBuf {
    let value = env::var_os(name).unwrap_or_else(|| {
        panic!("{name} must point to the directory containing the LaZer library")
    });
    let path = PathBuf::from(value);
    assert!(
        path.is_dir(),
        "{} is not a directory: {}",
        name,
        path.display()
    );
    path
}

fn main() {
    println!("cargo:rerun-if-changed=lazer/shim.c");
    println!("cargo:rerun-if-changed=lazer/shim.h");
    println!("cargo:rerun-if-changed=lazer/params_d64.h");
    println!("cargo:rerun-if-env-changed=LAZER_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LAZER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LAZER_HEXL_LIB_DIR");

    if env::var_os("CARGO_FEATURE_LAZER_FFI").is_none() {
        return;
    }

    let include_dir = required_dir("LAZER_INCLUDE_DIR");
    let lazer_dir = required_dir("LAZER_LIB_DIR");
    let hexl_dir = required_dir("LAZER_HEXL_LIB_DIR");

    cc::Build::new()
        .file("lazer/shim.c")
        .include(include_dir)
        .include("lazer")
        .flag_if_supported("-std=c11")
        .flag_if_supported("-pthread")
        .warnings(true)
        .compile("blind_sig_lazer_shim");

    println!("cargo:rustc-link-search=native={}", lazer_dir.display());
    println!("cargo:rustc-link-search=native={}", hexl_dir.display());
    println!("cargo:rustc-link-lib=static=lazer");
    println!("cargo:rustc-link-lib=static=hexl");
    println!("cargo:rustc-link-lib=mpfr");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=stdc++");
}
