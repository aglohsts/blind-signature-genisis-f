//! Integration tests for the LaZer-backed proof layer.
//! Report: "LaZer Integration" and "The Final-Signature Proof".
//!
//! These run only with the `lazer-ffi` feature, which needs the pinned
//! LaZer libraries; see `lazer/README.md`. Key generation at `d = 64`
//! is expensive, so each test does at most one of them.

#![cfg(feature = "lazer-ffi")]

use blind_sig::commitment_proof::{CommitmentProofProvider, LazerProof, LazerProvider};
use blind_sig::issue::{Response, UserState, signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, PublicKey, SecretKey, key_gen};
use blind_sig::lazer_ffi;
use blind_sig::module_lwe::ModuleLweEncoding;
use blind_sig::proof_com::ProofParameters;
use blind_sig::signature::{
    FinalSignatureProofProvider, LazerSignatureProvider, finalise_with_provider, relation_holds,
    signature_witness, verify_with_provider,
};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{MatrixSetEntry, SetCoefficient};
use qfall_tools::primitive::psf::PSFGPVRing;
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;

const D: i64 = 64;
const Q_MOD: u64 = 281_474_976_711_349;
const COM_SEED: [u8; 32] = [7; 32];
const SIG_SEED: [u8; 32] = [11; 32];

fn profile_keys() -> (PublicKey<ModuleLweEncoding>, SecretKey) {
    let psf = PSFGPVRing {
        gp: GadgetParametersRing::init_default(D, Q_MOD),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    };
    let function = ModuleLweEncoding::new(
        1,
        lazer_ffi::TAG_COEFFICIENTS as i64,
        lazer_ffi::FUNCTION_RANDOMNESS_COLUMNS as i64,
        3,
        psf.gp.modulus.clone(),
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
    key_gen(function, psf, parameters)
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

/// Runs the issuing protocol and returns what the user keeps.
fn honest_run(
    public_key: &PublicKey<ModuleLweEncoding>,
    secret_key: &SecretKey,
    message: &MatPolyOverZ,
    provider: &LazerProvider,
) -> (UserState, Response<ModuleLweEncoding>) {
    let (request, state) =
        user_request(public_key, message, provider).expect("the LaZer prover failed");
    assert_eq!(lazer_ffi::proof_len(), request.proof.as_bytes().len());
    let response =
        signer_respond(public_key, secret_key, &request, provider).expect("signer aborted");
    assert!(user_check(public_key, &state, &response));
    (state, response)
}

#[test]
fn the_profile_sizes_are_the_generated_ones() {
    assert_eq!(22_682, lazer_ffi::proof_len());
    assert_eq!(32_234, lazer_ffi::final_signature_proof_len());
    assert_eq!(55, lazer_ffi::BOUNDED_COLUMNS);
    assert!(!lazer_ffi::version().expect("LaZer version").is_empty());
}

/// The issuing protocol runs end to end with `pi_com` produced by
/// LaZer, and the proof is bound to its commitment and to the seed.
#[test]
fn the_lazer_commitment_proof_drives_the_issuing_protocol() {
    let (public_key, secret_key) = profile_keys();
    let provider = LazerProvider::new(COM_SEED);
    let message = profile_message(1, 1);

    let (request, state) = user_request(&public_key, &message, &provider).expect("prove");
    assert_eq!(lazer_ffi::proof_len(), request.proof.as_bytes().len());
    assert!(provider.verify(&public_key, &request.commitment, &request.proof));

    let other_commitment = &request.commitment + &request.commitment;
    assert!(!provider.verify(&public_key, &other_commitment, &request.proof));

    let other_seed = LazerProvider::new([9; 32]);
    assert!(!other_seed.verify(&public_key, &request.commitment, &request.proof));

    let response =
        signer_respond(&public_key, &secret_key, &request, &provider).expect("signer aborted");
    assert!(user_check(&public_key, &state, &response));
}

/// The full path: an honest run yields a witness for `R_sig`, the
/// proof verifies against the public message alone, and two sessions
/// on the same message give different proofs.
#[test]
fn the_lazer_final_signature_proof_verifies_and_hides_the_witness() {
    let (public_key, secret_key) = profile_keys();
    let commitment_provider = LazerProvider::new(COM_SEED);
    let signature_provider = LazerSignatureProvider::new(SIG_SEED);
    let message = profile_message(1, 1);

    let (state, response) = honest_run(&public_key, &secret_key, &message, &commitment_provider);
    let witness = signature_witness(&public_key, state, response);
    assert!(relation_holds(&public_key, &message, &witness));

    let first = signature_provider
        .prove(&public_key, &message, &witness)
        .expect("the LaZer final-signature prover failed");
    assert_eq!(
        lazer_ffi::final_signature_proof_len(),
        first.as_bytes().len()
    );

    let (state, response) = honest_run(&public_key, &secret_key, &message, &commitment_provider);
    let second = finalise_with_provider(&public_key, state, response, &signature_provider)
        .expect("prove");

    assert!(signature_provider.verify(&public_key, &message, &first));
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

    // The statement binds the message, so the proof does not carry over.
    assert!(!signature_provider.verify(&public_key, &profile_message(1, -1), &first));
}

/// A witness whose function randomness was changed no longer satisfies
/// `R_sig`, so the prover refuses it instead of emitting a proof that
/// cannot verify. This covers the block that the fixed-function
/// relation did not have.
#[test]
fn a_changed_function_randomness_is_refused_by_the_prover() {
    let (public_key, secret_key) = profile_keys();
    let commitment_provider = LazerProvider::new(COM_SEED);
    let signature_provider = LazerSignatureProvider::new(SIG_SEED);
    let message = profile_message(1, 1);

    let (state, response) = honest_run(&public_key, &secret_key, &message, &commitment_provider);
    let mut witness = signature_witness(&public_key, state, response);

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
    let psf = PSFGPVRing {
        gp: GadgetParametersRing::init_default(8, 257),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    };
    let function = ModuleLweEncoding::new(1, 10, 2, 3, psf.gp.modulus.clone());
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
    let (public_key, _) = key_gen(function, psf, parameters);
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
