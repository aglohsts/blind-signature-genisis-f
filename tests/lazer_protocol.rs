//! Integration tests for the LaZer-backed proof layer.
//! Report: "LaZer Integration" and "The Final-Signature Proof".
//!
//! These run only with the `lazer-ffi` feature, which needs the pinned
//! LaZer libraries; see `lazer/README.md`. Key generation at `d = 64`
//! dominates the cost of the whole suite, so the checks that need a
//! profile key share one, and the run below is written as a single
//! sequence through the protocol.

#![cfg(feature = "lazer-ffi")]

use blind_sig::commitment_proof::{CommitmentProofProvider, LazerProof, LazerProvider};
use blind_sig::issue::{signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, PublicKey, SecretKey, key_gen};
use blind_sig::lazer_ffi;
use blind_sig::module_lwe::ModuleLweEncoding;
use blind_sig::preimage::{Sampler, gadget_parameters};
use blind_sig::proof_com::ProofParameters;
use blind_sig::signature::{
    FinalSignatureProofProvider, LazerSignatureProvider, finalise_with_provider, relation_holds,
    signature_witness, verify_with_provider,
};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{MatrixSetEntry, SetCoefficient};
use std::time::Instant;

const D: i64 = 64;
const Q_MOD: u64 = 281_474_976_711_349;
const COM_SEED: [u8; 32] = [7; 32];
const SIG_SEED: [u8; 32] = [11; 32];

fn profile_keys() -> (PublicKey<ModuleLweEncoding>, SecretKey) {
    let sampler = Sampler::new(
        gadget_parameters(D, Q_MOD, 4),
        Q::from(100),
        Q::from(1.005_f64),
    );
    let function = ModuleLweEncoding::new(
        1,
        lazer_ffi::TAG_COEFFICIENTS as i64,
        lazer_ffi::FUNCTION_RANDOMNESS_COLUMNS as i64,
        3,
        sampler.modulus().clone(),
    );
    let parameters = Parameters {
        ell_m: 2,
        ell_r: 2,
        psi: 3,
        message_bound_sqrd: Z::from(lazer_ffi::PROFILE_MESSAGE_BOUND_SQ),
        proof: ProofParameters {
            witness_inf: 20,
            mask_inf: 8000,
        },
    };
    key_gen(function, sampler, parameters)
}

/// A sparse message that stays inside the profile bound
/// `||m||^2 <= 16`. A dense binary message over `d = 64` would not.
fn profile_message(first: i64, second: i64) -> MatPolyOverZ {
    let mut message = MatPolyOverZ::new(2, 1);
    let mut top = PolyOverZ::default();
    top.set_coeff(0, first).unwrap();
    top.set_coeff(5, 1).unwrap();
    let mut bottom = PolyOverZ::default();
    bottom.set_coeff(3, second).unwrap();
    message.set_entry(0, 0, &top).unwrap();
    message.set_entry(1, 0, &bottom).unwrap();
    message
}

/// Writes one stage timing to stderr, where `--nocapture` shows it.
fn report(stage: &str, started: Instant) {
    eprintln!("    {stage:<26}: {:>8.2} s", started.elapsed().as_secs_f64());
}

#[test]
fn the_profile_sizes_are_the_generated_ones() {
    assert_eq!(22_682, lazer_ffi::proof_len());
    assert_eq!(23_960, lazer_ffi::final_signature_proof_len());
    assert_eq!(19, lazer_ffi::BOUNDED_COLUMNS);
    assert!(!lazer_ffi::version().expect("LaZer version").is_empty());
}

/// One pass through the protocol with both proofs produced by LaZer.
/// The stages are separated by comments rather than by test functions,
/// because a profile key costs more to generate than every check here
/// costs to run.
///
/// Each stage reports its own elapsed time. The times are hidden unless
/// the suite runs with `--nocapture`, and they are the measurements the
/// evaluation reports, so they should be read from a release build.
#[test]
fn the_lazer_proof_layer_carries_the_protocol() {
    let started = Instant::now();
    let (public_key, secret_key) = profile_keys();
    report("key generation", started);
    let commitment_provider = LazerProvider::new(COM_SEED);
    let signature_provider = LazerSignatureProvider::new(SIG_SEED);
    let message = profile_message(1, 1);

    // Pi_com. The proof travels with the request, and it binds both the
    // commitment and the public-parameter seed.
    let started = Instant::now();
    let (request, state) =
        user_request(&public_key, &message, &commitment_provider).expect("the LaZer prover failed");
    report("user request, with pi_com", started);
    assert_eq!(lazer_ffi::proof_len(), request.proof.as_bytes().len());
    assert!(commitment_provider.verify(&public_key, &request.commitment, &request.proof));

    let other_commitment = &request.commitment + &request.commitment;
    assert!(!commitment_provider.verify(&public_key, &other_commitment, &request.proof));
    let other_seed = LazerProvider::new([9; 32]);
    assert!(!other_seed.verify(&public_key, &request.commitment, &request.proof));

    let started = Instant::now();
    let response = signer_respond(&public_key, &secret_key, &request, &commitment_provider)
        .expect("signer aborted");
    report("signer response", started);

    let started = Instant::now();
    assert!(user_check(&public_key, &state, &response));
    report("user check", started);

    // Pi_sig. The witness of the accepted run satisfies R_sig, and the
    // proof is checked against the public message alone.
    let mut witness = signature_witness(&public_key, state, response);
    assert!(relation_holds(&public_key, &message, &witness));

    let started = Instant::now();
    let first = signature_provider
        .prove(&public_key, &message, &witness)
        .expect("the LaZer final-signature prover failed");
    report("pi_sig, prove", started);
    assert_eq!(
        lazer_ffi::final_signature_proof_len(),
        first.as_bytes().len()
    );

    let started = Instant::now();
    assert!(signature_provider.verify(&public_key, &message, &first));
    report("pi_sig, verify", started);

    // The statement binds the message, so the proof does not carry over.
    assert!(!signature_provider.verify(&public_key, &profile_message(1, -1), &first));

    // A second session on the same message. The function input, the
    // function randomness and the commitment randomness are fresh, so
    // the two proofs differ.
    let (request, state) =
        user_request(&public_key, &message, &commitment_provider).expect("prove");
    let response = signer_respond(&public_key, &secret_key, &request, &commitment_provider)
        .expect("signer aborted");
    assert!(user_check(&public_key, &state, &response));
    let second = finalise_with_provider(&public_key, state, response, &signature_provider)
        .expect("prove");
    assert!(verify_with_provider(
        &public_key,
        &message,
        &second,
        &signature_provider
    ));
    assert_ne!(
        first.as_bytes(),
        second.proof.as_bytes(),
        "two sessions must not produce the same proof",
    );

    // Changing the function randomness leaves R_sig, so the prover
    // refuses the witness instead of producing a proof that cannot
    // verify. This reuses the witness of the first session.
    let mut shift = MatPolyOverZ::new(lazer_ffi::FUNCTION_RANDOMNESS_COLUMNS as i64, 1);
    shift.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
    witness.function_randomness = &witness.function_randomness + &shift;
    assert!(!relation_holds(&public_key, &message, &witness));
    assert_eq!(
        Err(lazer_ffi::Error::InvalidInput),
        signature_provider.prove(&public_key, &message, &witness)
    );
}

/// A public key outside the generated profile is rejected before any
/// call into LaZer. The toy ring is cheap, so this needs no `d = 64`
/// key generation.
#[test]
fn a_public_key_outside_the_profile_is_rejected() {
    let sampler = Sampler::new(
        gadget_parameters(8, 257, 1),
        Q::from(100),
        Q::from(1.005_f64),
    );
    let function = ModuleLweEncoding::new(1, 10, 2, 3, sampler.modulus().clone());
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
    let (public_key, _) = key_gen(function, sampler, parameters);
    let message = MatPolyOverZ::sample_uniform(2, 1, 7, 0, 2).unwrap();
    let randomness = public_key.commitment_key.sample_randomness();
    let commitment = public_key.commitment_key.commit(&message, &randomness);

    let provider = LazerProvider::new(COM_SEED);
    assert!(
        provider
            .prove(&public_key, &message, &randomness, &commitment)
            .is_err()
    );
    assert!(!provider.verify(
        &public_key,
        &commitment,
        &LazerProof::from_bytes(vec![0; lazer_ffi::proof_len()])
    ));
}
