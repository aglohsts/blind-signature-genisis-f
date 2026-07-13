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
    println!("cargo:rerun-if-env-changed=LAZER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LAZER_HEXL_LIB_DIR");

    if env::var_os("CARGO_FEATURE_LAZER_FFI").is_none() {
        return;
    }

    let lazer_dir = required_dir("LAZER_LIB_DIR");
    let hexl_dir = required_dir("LAZER_HEXL_LIB_DIR");

    println!("cargo:rustc-link-search=native={}", lazer_dir.display());
    println!("cargo:rustc-link-search=native={}", hexl_dir.display());
    println!("cargo:rustc-link-lib=static=lazer");
    println!("cargo:rustc-link-lib=static=hexl");
    println!("cargo:rustc-link-lib=mpfr");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=stdc++");
}
