// Report: "LaZer Integration Feasibility".

fn main() {
    match blind_sig::lazer_ffi::version() {
        Ok(version) => println!("Rust -> LaZer C FFI OK (LaZer {version})"),
        Err(error) => {
            eprintln!("Rust -> LaZer C FFI failed: {error}");
            std::process::exit(1);
        }
    }
}
