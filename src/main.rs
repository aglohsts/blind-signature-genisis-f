//! Demo: full protocol run for both tag functions. Toy parameters;
//! the proof layer is a transparent placeholder.

use blind_sig::issue::{signer_respond, user_check, user_commit};
use blind_sig::keys::key_gen;
use blind_sig::signature::{finalize, verify};
use blind_sig::tag_function::{BinaryEncoding, HashToRing, TagFunction};
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_tools::primitive::psf::PSFGPVRing;
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;

const D: i64 = 8;
const Q_MOD: u64 = 257;
const ELL_M: i64 = 2;
const ELL_R: i64 = 2;

fn toy_psf() -> PSFGPVRing {
    PSFGPVRing {
        gp: GadgetParametersRing::init_default(D, Q_MOD),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    }
}

fn run_protocol<F: TagFunction>(label: &str, f: F, psf: PSFGPVRing) {
    println!("--- {label} ---");
    let (pk, sk) = key_gen(f, psf, ELL_M, ELL_R, Q::from(3), Z::from(16), Z::from(2000));
    println!(
        "KeyGen: A is 1 x {} over R_q, N = {}",
        qfall_math::traits::MatrixDimensions::get_num_columns(&pk.a),
        pk.f.domain_size()
    );

    let m = MatPolyOverZ::sample_uniform(ELL_M, 1, D - 1, 0, 2).unwrap();
    let (msg, st) = user_commit(&pk, &m);
    println!("Step 1: user sends the commitment c = {}", msg.c);

    let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
    println!("Step 2: signer returns the tag x = {}", resp.x);

    let ok = user_check(&pk, &st, &resp);
    println!("Step 3: user check passed: {ok}");

    let sig = finalize(st, resp);
    println!("Step 4: verification result: {}\n", verify(&pk, &m, &sig));
}

fn main() {
    println!("== blind-sig full protocol demo (toy parameters) ==");
    println!("ring: R_q = Z_{Q_MOD}[X]/(X^{D} + 1), module rank n = 1");
    println!("NOTE: the proof layer is a transparent placeholder.\n");

    let psf = toy_psf();
    let f_hash = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "blind-sig-demo");
    run_protocol("HashToRing (random-oracle style), N = 2^20", f_hash, psf);

    let psf = toy_psf();
    let f_bin = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
    run_protocol("BinaryEncoding (BLNS Sec. 3.1.2), N = 2^10", f_bin, psf);
}
