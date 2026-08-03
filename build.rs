// report: "LaZer Integration"
//
// With the `lazer-ffi` feature off this script does nothing, which is
// what keeps `cargo test` working on any platform.
//
// With the feature on it needs three directories: one holding lazer.h,
// one holding liblazer.a, and one holding libhexl.a. They come from
// LAZER_INCLUDE_DIR, LAZER_LIB_DIR and LAZER_HEXL_LIB_DIR when those are
// set, and otherwise from building the copy of LaZer under
// third_party/lazer. The second path is the usual one; the environment
// variables are there so that an already built tree can be reused.

use std::process::Command;
use std::{env, fs, path::Path, path::PathBuf};

// Each patch, with a line from what it inserts and how many times that
// line should appear once the file is patched. A half-patched tree
// compiles without complaint and then fails inside the proof layer, so
// the result is checked rather than assumed.
const PATCHES: [(&str, &str, &str, usize); 2] = [
    (
        "0001-pass-input-equations-to-tbox.patch",
        "src/lnp.c",
        "R2prime + EVALEQ_INPUT_OFF",
        3,
    ),
    (
        "0002-initialise-sparse-encoding.patch",
        "src/coder.c",
        "zero unset bits in first byte",
        6,
    ),
];

fn count_lines_containing(file: &Path, needle: &str) -> usize {
    let text = fs::read_to_string(file)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
    text.lines().filter(|line| line.contains(needle)).count()
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
}

fn out_dir() -> PathBuf {
    PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"))
}

fn jobs() -> String {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .to_string()
}

fn note(message: &str) { // build script output is hidden unless it is a warning
    println!("cargo:warning={message}");
}

fn run(what: &str, command: &mut Command) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("{what} could not be started: {error}"));
    assert!(status.success(), "{what} failed with {status}");
}

// Only a spawn failure means the tool is absent. Several of these
// answer --version with a non-zero status, unzip among them, so the
// exit code says nothing about whether the tool is there.
fn require_tool(tool: &str) {
    let missing = matches!(
        Command::new(tool)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    assert!(
        !missing,
        "{tool} is needed to build LaZer but was not found on PATH.\n\
         Install the C and C++ compilers, make, cmake, patch and unzip,\n\
         or point LAZER_INCLUDE_DIR, LAZER_LIB_DIR and LAZER_HEXL_LIB_DIR\n\
         at a LaZer tree that is already built.",
    );
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap_or_else(|e| panic!("cannot create {}: {e}", to.display()));
    for entry in fs::read_dir(from).unwrap_or_else(|e| panic!("cannot read {}: {e}", from.display()))
    {
        let entry = entry.expect("directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target)
                .unwrap_or_else(|e| panic!("cannot copy to {}: {e}", target.display()));
        }
    }
}

// gmp-mpfr-sys builds both libraries from source during the first Cargo
// build, and a shared machine often has neither installed. OUT_DIR is
// `target/<profile>/build/<crate>-<hash>/out`, so its grandparent holds
// every build directory of this profile.
fn cargo_built_gmp() -> Option<(PathBuf, PathBuf)> { // (include, lib)
    let build_root = out_dir().parent()?.parent()?.to_path_buf();
    for entry in fs::read_dir(build_root).ok()? {
        let path = entry.ok()?.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("gmp-mpfr-sys-"))
        {
            continue;
        }
        let out = path.join("out");
        let (include, lib) = (out.join("include"), out.join("lib"));
        if include.join("mpfr.h").is_file() && lib.join("libmpfr.a").is_file() {
            return Some((include, lib));
        }
    }
    None
}

fn prepend_path(command: &mut Command, name: &str, value: &Path) {
    let existing = env::var(name).unwrap_or_default();
    let combined = if existing.is_empty() {
        value.display().to_string()
    } else {
        format!("{}:{existing}", value.display())
    };
    command.env(name, combined);
}

// The Makefile unzips and configures HEXL itself, but without
// -DCMAKE_POLICY_VERSION_MINIMUM. HEXL declares a cmake_minimum_required
// that CMake 4 refuses, so the step is done here instead and the
// directory is then given a fresh timestamp to stop make repeating it.
fn build_hexl(tree: &Path) {
    let third_party = tree.join("third_party");
    let hexl = third_party.join("hexl-development");

    run(
        "unzip of hexl-development.zip",
        Command::new("unzip")
            .current_dir(&third_party)
            .args(["-q", "-o", "hexl-development.zip"]),
    );
    run(
        "cmake configure of HEXL",
        Command::new("cmake").current_dir(&third_party).args([
            "-S",
            "hexl-development",
            "-B",
            "hexl-development/build",
            "-DHEXL_BENCHMARK=OFF",
            "-DHEXL_TESTING=OFF",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
        ]),
    );
    run(
        "cmake build of HEXL",
        Command::new("cmake")
            .current_dir(&third_party)
            .args(["--build", "hexl-development/build", "-j", &jobs()]),
    );
    run(
        "touch of the HEXL directory",
        Command::new("touch").arg(&hexl),
    );
}

// cmake writes to lib on some distributions and lib64 on others.
fn hexl_lib_dir(tree: &Path) -> PathBuf {
    let base = tree.join("third_party/hexl-development/build/hexl");
    for name in ["lib", "lib64"] {
        let candidate = base.join(name);
        if candidate.join("libhexl.a").is_file() {
            return candidate;
        }
    }
    panic!(
        "libhexl.a was not found under {}. The HEXL build reported success \
         but produced nothing.",
        base.display()
    );
}

fn build_vendored() -> (PathBuf, PathBuf, PathBuf) {
    let manifest = manifest_dir();
    let source = manifest.join("third_party/lazer");
    assert!(
        source.join("Makefile").is_file(),
        "third_party/lazer is missing or incomplete: {} has no Makefile.\n\
         It holds the pinned LaZer source and should have been supplied\n\
         with this project; see third_party/README.md.",
        source.display(),
    );

    let tree = out_dir().join("lazer");
    let archive = tree.join("liblazer.a");
    if !archive.is_file() {
        for tool in ["cc", "make", "cmake", "patch", "unzip", "touch"] {
            require_tool(tool);
        }
        note(
            "building the LaZer library from third_party/lazer. This runs \
             once and takes 5 to 15 minutes.",
        );

        if tree.exists() {
            fs::remove_dir_all(&tree).expect("clearing a partial LaZer build");
        }
        copy_tree(&source, &tree);

        // Applied here rather than shipped pre-applied, so that the two
        // defects the report describes stay readable as patches.
        for (patch, target, marker, expected) in PATCHES {
            let file = manifest.join("lazer/patches").join(patch);
            run(
                &format!("applying {patch}"),
                Command::new("patch").args([
                    "--directory".as_ref(),
                    tree.as_os_str(),
                    "--strip=1".as_ref(),
                    "--forward".as_ref(),
                    "--input".as_ref(),
                    file.as_os_str(),
                ]),
            );
            let patched = tree.join(target);
            let found = count_lines_containing(&patched, marker);
            assert_eq!(
                found, expected,
                "{patch} did not apply cleanly: {target} has {found} lines                  containing {marker:?}, expected {expected}.",
            );
        }

        build_hexl(&tree);

        let mut make = Command::new("make");
        make.arg("-C").arg(&tree).arg("lib-static").arg("-j").arg(jobs());
        if let Some((include, lib)) = cargo_built_gmp() {
            prepend_path(&mut make, "CPATH", &include);
            prepend_path(&mut make, "LIBRARY_PATH", &lib);
        }
        run("make lib-static", &mut make);

        note("the LaZer library is built.");
    }

    assert!(
        tree.join("lazer.h").is_file(),
        "make reported success but did not produce lazer.h in {}",
        tree.display(),
    );
    let hexl = hexl_lib_dir(&tree);
    (tree.clone(), tree, hexl)
}

fn resolved_dir(name: &str) -> PathBuf {
    let path = PathBuf::from(env::var_os(name).expect("checked by the caller"));
    assert!(
        path.is_dir(),
        "{name} is not a directory: {}",
        path.display()
    );
    // Linker search paths are passed to rustc verbatim, so a relative
    // value would be resolved against a directory this script does not
    // control.
    path.canonicalize()
        .unwrap_or_else(|error| panic!("{} cannot be resolved: {error}", path.display()))
}

fn prebuilt_from_env() -> Option<(PathBuf, PathBuf, PathBuf)> {
    const NAMES: [&str; 3] = [
        "LAZER_INCLUDE_DIR",
        "LAZER_LIB_DIR",
        "LAZER_HEXL_LIB_DIR",
    ];
    let set: Vec<&str> = NAMES
        .iter()
        .copied()
        .filter(|name| env::var_os(name).is_some())
        .collect();
    if set.is_empty() {
        return None;
    }
    assert_eq!(
        set.len(),
        NAMES.len(),
        "only {set:?} of {NAMES:?} are set. Set all three to use a LaZer \
         tree that is already built, or none to build third_party/lazer.",
    );

    let include = resolved_dir(NAMES[0]);
    let lazer = resolved_dir(NAMES[1]);
    let hexl = resolved_dir(NAMES[2]);
    assert!(
        include.join("lazer.h").is_file(),
        "lazer.h was not found in {}",
        include.display()
    );
    assert!(
        lazer.join("liblazer.a").is_file(),
        "liblazer.a was not found in {}",
        lazer.display()
    );
    assert!(
        hexl.join("libhexl.a").is_file(),
        "libhexl.a was not found in {}",
        hexl.display()
    );
    Some((include, lazer, hexl))
}

fn main() {
    println!("cargo:rerun-if-changed=lazer/shim.c");
    println!("cargo:rerun-if-changed=lazer/shim_sig.c");
    println!("cargo:rerun-if-changed=lazer/shim_sig_statement.c");
    println!("cargo:rerun-if-changed=lazer/shim_sig_statement.h");
    println!("cargo:rerun-if-changed=lazer/shim.h");
    println!("cargo:rerun-if-changed=lazer/params_d64.h");
    println!("cargo:rerun-if-changed=lazer/params_sig_d64.h");
    println!("cargo:rerun-if-changed=lazer/patches");
    println!("cargo:rerun-if-changed=lazer/LAZER_REVISION");
    println!("cargo:rerun-if-env-changed=LAZER_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=LAZER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LAZER_HEXL_LIB_DIR");

    if env::var_os("CARGO_FEATURE_LAZER_FFI").is_none() {
        return;
    }

    let (include_dir, lazer_dir, hexl_dir) =
        prebuilt_from_env().unwrap_or_else(build_vendored);

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
    if let Some((_, gmp_lib)) = cargo_built_gmp() {
        println!("cargo:rustc-link-search=native={}", gmp_lib.display());
    }
    println!("cargo:rustc-link-lib=static=lazer");
    println!("cargo:rustc-link-lib=static=hexl");
    println!("cargo:rustc-link-lib=mpfr");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=stdc++");
}
