// report: "Evaluation", functional correctness
// integration tests: the full protocol through the public interface

use blind_sig::binary_encoding::BinaryEncoding;
use blind_sig::commitment_proof::FiatShamirProvider;
use blind_sig::hash_to_ring::HashToRing;
use blind_sig::issue::{SignerAbort, signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, PublicKey, SecretKey, key_gen};
use blind_sig::preimage::{Sampler, Sampling, gadget_parameters};
use blind_sig::proof_com::ProofParameters;
use blind_sig::signature::{Signature, finalise, verify};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{MatrixDimensions, MatrixSetEntry};

const D: i64 = 8;
const Q_MOD: u64 = 257;

fn keys(separator: &str) -> (PublicKey<HashToRing>, SecretKey) {
    keys_with(separator, Sampling::default())
}

// the protocol is run under both preimage samplers, so every claim about an honest run is asserted for each
fn keys_with(separator: &str, sampling: Sampling) -> (PublicKey<HashToRing>, SecretKey) {
    let sampler = Sampler::with_sampling(
        gadget_parameters(D, Q_MOD, 1),
        Q::from(100),
        Q::from(1.005_f64),
        sampling,
    );
    let function = HashToRing::new(
        1,
        1u64 << 10,
        1u64 << 20,
        1u64 << 10,
        sampler.modulus().clone(),
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
    key_gen(function, sampler, parameters)
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
    for sampling in Sampling::ALL {
        let (public_key, secret_key) = keys_with("honest", sampling);
        assert_eq!(sampling, public_key.sampler.sampling());
        let message = sample_message();
        let signature = honest_run(&public_key, &secret_key, &message);
        assert!(verify(&public_key, &message, &signature), "{sampling}");
    }
}

#[test]
fn ten_honest_runs_verify_under_one_key() {
    for sampling in Sampling::ALL {
        let (public_key, secret_key) = keys_with("repeat", sampling);
        for _ in 0..10 {
            let message = sample_message();
            let signature = honest_run(&public_key, &secret_key, &message);
            assert!(verify(&public_key, &message, &signature), "{sampling}");
        }
    }
}

// a signature made under one sampler verifies under a key using the other, which is what interchangeable means here
#[test]
fn either_sampler_produces_signatures_the_other_key_verifies() {
    let (stored_key, stored_secret) = keys_with("swap", Sampling::StoredBasis);
    let message = sample_message();
    let from_stored = honest_run(&stored_key, &stored_secret, &message);

    let per_call_key = PublicKey {
        sampler: Sampler::with_sampling(
            gadget_parameters(D, Q_MOD, 1),
            Q::from(100),
            Q::from(1.005_f64),
            Sampling::PerCall,
        ),
        ..stored_key
    };
    assert!(verify(&per_call_key, &message, &from_stored));

    let from_per_call = honest_run(&per_call_key, &stored_secret, &message);
    assert!(verify(&per_call_key, &message, &from_per_call));
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
    assert_eq!(
        Err(SignerAbort::ProofRejected),
        signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider).map(|_| ()),
    );
}

// two runs on the same message use fresh randomness, so the requests differ (the behaviour that blindness relies on)
#[test]
fn two_runs_on_one_message_send_different_requests() {
    let (public_key, _) = keys("fresh");
    let message = sample_message();
    let (first, _) = user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
    let (second, _) = user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
    assert_ne!(first.commitment, second.commitment);
}

// report: "Scope and Design Goals"
#[test]
fn the_protocol_carries_the_fixed_function_too() {
    let sampler = Sampler::new(
        gadget_parameters(D, Q_MOD, 1),
        Q::from(100),
        Q::from(1.005_f64),
    );
    let function = BinaryEncoding::new(1, 10, sampler.modulus().clone());
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
    let (public_key, secret_key) = key_gen(function, sampler, parameters);
    let message = sample_message();

    let (request, state) =
        user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
    let response = signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider)
        .expect("signer aborted");
    assert!(user_check(&public_key, &state, &response));

    let signature = finalise(state, response);
    assert!(verify(&public_key, &message, &signature));

    // The key and the randomness are the unit type here, so the only
    // thing a session varies is the function input.
    let other = &message + &message;
    assert!(!verify(&public_key, &other, &signature));
}
