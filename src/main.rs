//! Demo: one full protocol run, then the two public functions. Toy
//! parameters, not cryptographically sized.

use blind_sig::binary_encoding::BinaryEncoding;
use blind_sig::commitment_proof::FiatShamirProvider;
use blind_sig::hash_to_ring::HashToRing;
use blind_sig::issue::{signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, key_gen};
use blind_sig::preimage::{Sampler, gadget_parameters};
use blind_sig::proof_com::ProofParameters;
use blind_sig::public_function::PublicFunction;
use blind_sig::signature::{finalise, verify};
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::rational::Q;

const D: i64 = 8;
const Q_MOD: u64 = 257;

fn main() {
    println!("== blind-sig demo (toy parameters) ==");
    println!("ring: R_q = Z_{Q_MOD}[X]/(X^{D} + 1), module rank n = 1");
    println!("NOTE: pi_sig is transparent; pi_com is a Fiat-Shamir proof.\n");

    let sampler = Sampler::new(
        gadget_parameters(D, Q_MOD, 1),
        Q::from(100),
        Q::from(1.005_f64),
    );
    let modulus = sampler.modulus().clone();
    let function = HashToRing::new(1, 1u64 << 10, 1u64 << 20, 1u64 << 10, modulus.clone(), "demo");
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
    println!("KeyGen: kappa = {}", public_key.function_key);

    let message = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
    let (request, state) =
        user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
    println!("Step 1: the user sends the commitment and its proof");

    let response = signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider)
        .expect("signer aborted");
    println!(
        "Step 2: the signer checked the proof and returns mu = {}, xi = {}",
        response.function_input, response.function_randomness
    );

    println!(
        "Step 3: the user check passes: {}",
        user_check(&public_key, &state, &response)
    );

    let signature = finalise(state, response);
    println!(
        "Step 4: verification returns {}\n",
        verify(&public_key, &message, &signature)
    );

    let binary_function = BinaryEncoding::new(1, 10, modulus);
    println!(
        "BinaryEncoding, the fixed function, input space [{}]",
        binary_function.input_space()
    );
    for input in [1u64, 2] {
        let input = Z::from(input);
        println!("  f({input}) = {}", binary_function.eval(&(), &input, &()));
    }
}
