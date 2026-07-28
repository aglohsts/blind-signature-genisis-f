//! Integration tests: the full protocol through the public interface.
//! Report: "Evaluation", functional correctness.

use blind_sig::commitment_proof::FiatShamirProvider;
use blind_sig::hash_to_ring::HashToRing;
use blind_sig::issue::{signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, PublicKey, SecretKey, key_gen};
use blind_sig::proof_com::ProofParameters;
use blind_sig::signature::{Signature, finalise, verify};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{MatrixDimensions, MatrixSetEntry};
use qfall_tools::primitive::psf::PSFGPVRing;
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;

const D: i64 = 8;
const Q_MOD: u64 = 257;

fn keys(separator: &str) -> (PublicKey<HashToRing>, SecretKey) {
    let psf = PSFGPVRing {
        gp: GadgetParametersRing::init_default(D, Q_MOD),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    };
    let function = HashToRing::new(
        1,
        1u64 << 10,
        1u64 << 20,
        1u64 << 10,
        psf.gp.modulus.clone(),
        separator,
    );
    let parameters = Parameters {
        ell_m: 2,
        ell_r: 2,
        psi: 3,
        message_bound_sqrd: Z::from(16),
        proof: ProofParameters {
            witness_inf: 20,
            mask_inf: 8000,
        },
    };
    key_gen(function, psf, parameters)
}

fn sample_message() -> MatPolyOverZ {
    MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap()
}

fn honest_run(
    public_key: &PublicKey<HashToRing>,
    secret_key: &SecretKey,
    message: &MatPolyOverZ,
) -> Signature<HashToRing> {
    let (request, state) =
        user_request(public_key, message, &FiatShamirProvider).expect("proof");
    let response = signer_respond(public_key, secret_key, &request, &FiatShamirProvider)
        .expect("signer aborted");
    assert!(user_check(public_key, &state, &response));
    finalise(state, response)
}

#[test]
fn an_honest_signature_verifies() {
    let (public_key, secret_key) = keys("honest");
    let message = sample_message();
    let signature = honest_run(&public_key, &secret_key, &message);
    assert!(verify(&public_key, &message, &signature));
}

#[test]
fn ten_honest_runs_verify_under_one_key() {
    let (public_key, secret_key) = keys("repeat");
    for _ in 0..10 {
        let message = sample_message();
        let signature = honest_run(&public_key, &secret_key, &message);
        assert!(verify(&public_key, &message, &signature));
    }
}

#[test]
fn tampered_signatures_are_rejected() {
    let (public_key, secret_key) = keys("tampered");
    let message = sample_message();

    let signature = honest_run(&public_key, &secret_key, &message);
    let other_message = &message + &message;
    assert!(!verify(&public_key, &other_message, &signature));

    let mut changed_input = honest_run(&public_key, &secret_key, &message);
    changed_input.function_input = &changed_input.function_input + &Z::ONE;
    assert!(!verify(&public_key, &message, &changed_input));

    let mut changed_randomness = honest_run(&public_key, &secret_key, &message);
    changed_randomness.function_randomness = &changed_randomness.function_randomness + &Z::ONE;
    assert!(!verify(&public_key, &message, &changed_randomness));

    let mut changed_preimage = honest_run(&public_key, &secret_key, &message);
    changed_preimage.preimage = &changed_preimage.preimage + &changed_preimage.preimage;
    assert!(!verify(&public_key, &message, &changed_preimage));

    let mut shifted = honest_run(&public_key, &secret_key, &message);
    let mut shift = MatPolyOverZ::new(shifted.preimage.get_num_rows(), 1);
    shift.set_entry(0, 0, PolyOverZ::from(10 * Q_MOD)).unwrap();
    shifted.preimage = &shifted.preimage + &shift;
    assert!(!verify(&public_key, &message, &shifted));
}

#[test]
fn an_invalid_proof_makes_the_signer_abort() {
    let (public_key, secret_key) = keys("bad-proof");
    let message = sample_message();
    let (mut request, _) =
        user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
    request.proof.message_response =
        &request.proof.message_response + &request.proof.message_response;
    assert!(signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider).is_none());
}

/// Two runs on the same message use fresh randomness, so the requests
/// differ. This is the behaviour that blindness relies on.
#[test]
fn two_runs_on_one_message_send_different_requests() {
    let (public_key, _) = keys("fresh");
    let message = sample_message();
    let (first, _) = user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
    let (second, _) = user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
    assert_ne!(first.commitment, second.commitment);
}
