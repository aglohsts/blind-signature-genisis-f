// report: "LaZer Integration"

use std::{env, path::PathBuf};

// The linker search paths are passed to rustc verbatim, so a relative
// value here would be resolved against a working directory this
// script does not control.
fn required_dir(name: &str) -> PathBuf { // resolve one of the LaZer directories to an absolute path
    let value = env::var_os(name).unwrap_or_else(|| {
        panic!("{name} must point to the directory containing the LaZer library")
    });
    let path = PathBuf::from(value);
    assert!(
        path.is_dir(),
        "{} is not a directory: {}\nFollow Step 2 of README.md first.",
        name,
        path.display()
    );
    path.canonicalize()
        .unwrap_or_else(|error| panic!("{} cannot be resolved: {error}", path.display()))
}

fn required_archive(dir: &PathBuf, file: &str, variable: &str) { // fail with an actionable message rather than leaving a missing archive to the linker
    let path = dir.join(file);
    assert!(
        path.is_file(),
        "{} was not found in {}, which {} points at.\n\
         The directory exists but the library was not built. Follow\n\
         Step 2 of README.md and check that each step succeeds.",
        file,
        dir.display(),
        variable,
    );
}

// LaZer links against the same two libraries, and a shared machine
// often has neither installed, so the linker is pointed at that copy
// when one exists. `OUT_DIR` is
// `target/<profile>/build/<crate>-<hash>/out`, so its grandparent
// holds every build directory of this profile.
fn cargo_built_gmp_dir() -> Option<PathBuf> { // locate the GMP and MPFR that qFALL builds through gmp-mpfr-sys
    let out_dir = PathBuf::from(env::var_os("OUT_DIR")?);
    let build_root = out_dir.parent()?.parent()?;
    for entry in std::fs::read_dir(build_root).ok()? {
        let path = entry.ok()?.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("gmp-mpfr-sys-"))
        {
            continue;
        }
        let lib = path.join("out").join("lib");
        if lib.join("libmpfr.a").is_file() && lib.join("libgmp.a").is_file() {
            return Some(lib);
        }
    }
    None
}

fn main() {
    println!("cargo:rerun-if-changed=lazer/shim.c");
    println!("cargo:rerun-if-changed=lazer/shim_sig.c");
    println!("cargo:rerun-if-changed=lazer/shim_sig_statement.c");
    println!("cargo:rerun-if-changed=lazer/shim_sig_statement.h");
    println!("cargo:rerun-if-changed=lazer/shim.h");
    println!("cargo:rerun-if-changed=lazer/params_d64.h");
    println!("cargo:rerun-if-changed=lazer/params_sig_d64.h");
    println!("cargo:rerun-if-env-changed=LAZER_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LAZER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LAZER_HEXL_LIB_DIR");

    if env::var_os("CARGO_FEATURE_LAZER_FFI").is_none() {
        return;
    }

    let include_dir = required_dir("LAZER_INCLUDE_DIR");
    let lazer_dir = required_dir("LAZER_LIB_DIR");
    let hexl_dir = required_dir("LAZER_HEXL_LIB_DIR");

    assert!(
        include_dir.join("lazer.h").is_file(),
        "lazer.h was not found in {}, which LAZER_INCLUDE_DIR points at.\n\
         Follow Step 2 of README.md and check that each step succeeds.",
        include_dir.display(),
    );
    required_archive(&lazer_dir, "liblazer.a", "LAZER_LIB_DIR");
    required_archive(&hexl_dir, "libhexl.a", "LAZER_HEXL_LIB_DIR");

    cc::Build::new()
        .file("lazer/shim.c")
        .file("lazer/shim_sig.c")
        .file("lazer/shim_sig_statement.c")
        .include(include_dir)
        .include("lazer")
        .flag_if_supported("-std=c11")
        .flag_if_supported("-pthread")
        .warnings(true)
        .compile("blind_sig_lazer_shim");

    println!("cargo:rustc-link-search=native={}", lazer_dir.display());
    println!("cargo:rustc-link-search=native={}", hexl_dir.display());
    if let Some(gmp_dir) = cargo_built_gmp_dir() {
        println!("cargo:rustc-link-search=native={}", gmp_dir.display());
    }
    println!("cargo:rustc-link-lib=static=lazer");
    println!("cargo:rustc-link-lib=static=hexl");
    println!("cargo:rustc-link-lib=mpfr");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=stdc++");
}
