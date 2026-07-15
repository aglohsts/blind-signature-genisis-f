// Report: "LaZer Integration Feasibility".

fn main() {
    match blind_sig::lazer_ffi::version() {
        Ok(version) => {
            println!("Rust -> LaZer C FFI OK (LaZer {version})");
            println!(
                "proof bytes: commitment {}, final signature {}, guarded {}",
                blind_sig::lazer_ffi::proof_len(),
                blind_sig::lazer_ffi::final_signature_proof_len(),
                blind_sig::lazer_ffi::final_signature_proof_capacity(),
            );
        }
        Err(error) => {
            eprintln!("Rust -> LaZer C FFI failed: {error}");
            std::process::exit(1);
        }
    }
}
