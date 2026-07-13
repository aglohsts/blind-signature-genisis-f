//! Integration tests: the full protocol for both tag functions.
//! Report: "Evaluation", functional correctness.

use blind_sig::issue::{signer_respond, user_check, user_commit};
use blind_sig::keys::{key_gen, KeyGenParams, PublicKey, SecretKey};
use blind_sig::proof_com::ComProofParams;
use blind_sig::signature::{finalize, verify, TransparentSignature};
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

fn keys<F: TagFunction>(f: F) -> (PublicKey<F>, SecretKey) {
    key_gen(
        f,
        toy_psf(),
        KeyGenParams {
            ell_m: ELL_M,
            ell_r: ELL_R,
            s_r: Q::from(3),
            beta_msg_sqrd: Z::from(16),
            beta_r_sqrd: Z::from(2000),
            com_params: ComProofParams {
                witness_inf: 20,
                mask_inf: 8000,
            },
        },
    )
}

fn sample_message() -> MatPolyOverZ {
    MatPolyOverZ::sample_uniform(ELL_M, 1, D - 1, 0, 2).unwrap()
}

fn honest_run<F: TagFunction>(
    pk: &PublicKey<F>,
    sk: &SecretKey,
    m: &MatPolyOverZ,
) -> TransparentSignature {
    let (msg, st) = user_commit(pk, m);
    let resp = signer_respond(pk, sk, &msg).expect("signer aborted");
    assert!(user_check(pk, &st, &resp));
    finalize(st, resp)
}

fn run_honest_and_tampered<F: TagFunction>(f: F) {
    let (pk, sk) = keys(f);
    let m = sample_message();

    // Honest run: the signature verifies.
    let sig = honest_run(&pk, &sk, &m);
    assert!(verify(&pk, &m, &sig));

    // A different message fails.
    let other_m = &m + &m;
    assert!(!verify(&pk, &other_m, &sig));

    // A tampered tag fails.
    let mut bad_tag = honest_run(&pk, &sk, &m);
    bad_tag.x = &bad_tag.x + &Z::ONE;
    assert!(!verify(&pk, &m, &bad_tag));

    // A tampered preimage fails.
    let mut bad_s = honest_run(&pk, &sk, &m);
    bad_s.s = &bad_s.s + &bad_s.s;
    assert!(!verify(&pk, &m, &bad_s));

    // Tampered commitment randomness fails.
    let mut bad_r = honest_run(&pk, &sk, &m);
    bad_r.r = &bad_r.r + &bad_r.r;
    assert!(!verify(&pk, &m, &bad_r));

    // An invalid commitment proof makes the signer abort.
    let (mut msg, _) = user_commit(&pk, &m);
    msg.proof.z_m = &msg.proof.z_m + &msg.proof.z_m;
    assert!(signer_respond(&pk, &sk, &msg).is_none());
}

#[test]
fn hash_to_ring_protocol() {
    let psf = toy_psf();
    let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "integration");
    run_honest_and_tampered(f);
}

#[test]
fn binary_encoding_protocol() {
    let psf = toy_psf();
    let f = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
    run_honest_and_tampered(f);
}

#[test]
fn repeated_honest_runs_succeed() {
    let psf = toy_psf();
    let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "integration-rep");
    let (pk, sk) = keys(f);
    for _ in 0..10 {
        let m = sample_message();
        let sig = honest_run(&pk, &sk, &m);
        assert!(verify(&pk, &m, &sig));
    }
}
