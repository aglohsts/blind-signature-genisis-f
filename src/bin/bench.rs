//! Benchmark: step timings and size estimates. Toy parameters; run
//! with --release. Report: "Evaluation".

use blind_sig::binary_encoding::BinaryEncoding;
use blind_sig::commitment_proof::FiatShamirProvider;
use blind_sig::hash_to_ring::HashToRing;
use blind_sig::issue::{signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, PublicKey, SecretKey, key_gen};
use blind_sig::proof_com::ProofParameters;
use blind_sig::public_function::PublicFunction;
use blind_sig::signature::{finalise, verify};
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{IntoCoefficientEmbedding, MatrixDimensions};
use qfall_tools::primitive::psf::PSFGPVRing;
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;
use std::hint::black_box;
use std::time::Instant;

const D: i64 = 8;
const Q_MOD: u64 = 257;
const ELL_M: i64 = 2;
const ELL_R: i64 = 2;
const PSI: i64 = 3;
const REPS: u32 = 20;

fn toy_psf() -> PSFGPVRing {
    PSFGPVRing {
        gp: GadgetParametersRing::init_default(D, Q_MOD),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    }
}

fn toy_parameters() -> Parameters {
    Parameters {
        ell_m: ELL_M,
        ell_r: ELL_R,
        psi: PSI,
        message_bound_sqrd: Z::from(16),
        proof: ProofParameters {
            witness_inf: 20,
            mask_inf: 8000,
        },
    }
}

fn fresh_keys() -> (PublicKey<HashToRing>, SecretKey) {
    let psf = toy_psf();
    let function = HashToRing::new(
        1,
        1u64 << 10,
        1u64 << 20,
        1u64 << 10,
        psf.gp.modulus.clone(),
        "bench",
    );
    key_gen(function, psf, toy_parameters())
}

fn time_ms<T>(reps: u32, mut action: impl FnMut() -> T) -> f64 {
    let start = Instant::now();
    for _ in 0..reps {
        black_box(action());
    }
    start.elapsed().as_secs_f64() * 1000.0 / reps as f64
}

fn max_abs_coeff(vector: &MatPolyOverZ) -> i64 {
    let norm = vector
        .clone()
        .into_coefficient_embedding(D)
        .norm_l_infty_infty();
    i64::try_from(&norm).unwrap()
}

fn bits_for(max_abs: i64) -> u32 {
    64 - (2 * max_abs.unsigned_abs() + 1).leading_zeros()
}

fn packed_bytes(coefficients: i64, bits: u32) -> i64 {
    (coefficients * bits as i64 + 7) / 8
}

fn main() {
    println!("== blind-sig benchmark (toy parameters, d = {D}, q = {Q_MOD}) ==");

    let keygen_ms = time_ms(REPS, fresh_keys);
    let (public_key, secret_key) = fresh_keys();
    let message = MatPolyOverZ::sample_uniform(ELL_M, 1, D - 1, 0, 2).unwrap();

    let key = public_key.function_key.clone();
    let input = Z::from(3);
    let randomness = Z::from(5);
    let hash_eval_ms = time_ms(1000, || public_key.function.eval(&key, &input, &randomness));

    let binary_function = BinaryEncoding::new(1, 10, public_key.function.modulus().clone());
    let binary_eval_ms = time_ms(1000, || binary_function.eval(&(), &input, &()));

    let request_ms = time_ms(REPS, || {
        user_request(&public_key, &message, &FiatShamirProvider).unwrap()
    });
    let (request, state) =
        user_request(&public_key, &message, &FiatShamirProvider).unwrap();
    let respond_ms = time_ms(REPS, || {
        signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider).unwrap()
    });
    let response =
        signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider).unwrap();
    let check_ms = time_ms(REPS, || user_check(&public_key, &state, &response));

    let (second_request, second_state) =
        user_request(&public_key, &message, &FiatShamirProvider).unwrap();
    let second_response =
        signer_respond(&public_key, &secret_key, &second_request, &FiatShamirProvider).unwrap();
    assert!(user_check(&public_key, &second_state, &second_response));
    let signature = finalise(second_state, second_response);
    assert!(verify(&public_key, &message, &signature));
    let verify_ms = time_ms(REPS, || verify(&public_key, &message, &signature));

    println!("\ntimings (mean, ms):");
    println!("  key generation          : {keygen_ms:8.2}");
    println!("  f eval, hash (1000)     : {hash_eval_ms:8.4}");
    println!("  f eval, binary (1000)   : {binary_eval_ms:8.4}");
    println!("  user request and prove  : {request_ms:8.2}");
    println!("  signer response         : {respond_ms:8.2}");
    println!("  user check              : {check_ms:8.2}");
    println!("  verification            : {verify_ms:8.2}");

    let modulus_bits = 9;
    let response_bits = bits_for(public_key.proof_parameters.response_inf(D));
    let preimage_bits = bits_for(max_abs_coeff(&signature.preimage));
    let randomness_bits = bits_for(max_abs_coeff(&signature.randomness));
    let space_bits = 20;
    let preimage_rows = public_key.a.get_num_columns();

    let commitment_bytes = packed_bytes(D, modulus_bits);
    let proof_bytes = packed_bytes(D, 2) + packed_bytes((ELL_M + ELL_R) * D, response_bits);
    let response_bytes =
        packed_bytes(preimage_rows * D, preimage_bits) + 2 * (space_bits as i64 + 7) / 8;
    let signature_bytes = response_bytes + packed_bytes(ELL_R * D, randomness_bits);

    println!("\nsize estimates (packed coefficients, bytes):");
    println!("  request (c, pi_com)     : {}", commitment_bytes + proof_bytes);
    println!("  response (mu, xi, s)    : {response_bytes}");
    println!("  signature (mu, xi, s, r): {signature_bytes}");
}
