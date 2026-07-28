//! Finalisation and verification with a transparent signature.
//! Report: "Finalisation" and "Verification".
//!
//! The signature carries the witness in the clear, so it works for
//! every public function but provides no blindness. The proof-based
//! path is added with the final-signature relation.

use crate::issue::{Response, UserState};
use crate::keys::PublicKey;
use crate::public_function::PublicFunction;
use crate::util::norm_eucl_sqrd;
use qfall_math::integer::MatPolyOverZ;
use qfall_tools::primitive::psf::PSF;

/// A transparent signature. It carries the witness in the clear, so it
/// gives no blindness.
pub struct Signature<F: PublicFunction> {
    pub function_input: F::Input,
    pub function_randomness: F::Randomness,
    pub preimage: MatPolyOverZ,
    pub randomness: MatPolyOverZ,
}

/// Step 4: the user builds the signature from its state and the
/// response. The caller runs the user check first.
pub fn finalise<F: PublicFunction>(state: UserState, response: Response<F>) -> Signature<F> {
    Signature {
        function_input: response.function_input,
        function_randomness: response.function_randomness,
        preimage: response.preimage,
        randomness: state.randomness,
    }
}

/// Checks the final relation directly on the witness.
pub fn verify<F: PublicFunction>(
    public_key: &PublicKey<F>,
    message: &MatPolyOverZ,
    signature: &Signature<F>,
) -> bool {
    let degree = public_key.function.modulus().get_degree();
    // The norm bounds come first because the reused f_a asserts them.
    public_key
        .function
        .contains_input(&signature.function_input)
        && public_key
            .function
            .contains_randomness(&signature.function_randomness)
        && public_key.psf.check_domain(&signature.preimage)
        && norm_eucl_sqrd(message, degree) <= public_key.message_bound_sqrd
        && norm_eucl_sqrd(&signature.randomness, degree)
            <= public_key.commitment_key.randomness_bound_sqrd()
        && public_key.psf.f_a(&public_key.a, &signature.preimage)
            == &public_key.function.eval(
                &public_key.function_key,
                &signature.function_input,
                &signature.function_randomness,
            ) + &public_key
                .commitment_key
                .commit(message, &signature.randomness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_proof::FiatShamirProvider;
    use crate::hash_to_ring::HashToRing;
    use crate::issue::{signer_respond, user_check, user_request};
    use crate::keys::{
        SecretKey, key_gen,
        tests::{toy_function, toy_parameters, toy_psf},
    };
    use qfall_math::integer::{PolyOverZ, Z};
    use qfall_math::traits::{MatrixDimensions, MatrixSetEntry};

    const D: i64 = 8;
    const Q_MOD: u64 = 257;

    fn setup() -> (PublicKey<HashToRing>, SecretKey, MatPolyOverZ) {
        let psf = toy_psf();
        let function = toy_function(&psf, "signature-test");
        let (public_key, secret_key) = key_gen(function, psf, toy_parameters());
        let message = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        (public_key, secret_key, message)
    }

    fn honest_signature(
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
    fn honest_signature_verifies() {
        let (public_key, secret_key, message) = setup();
        let signature = honest_signature(&public_key, &secret_key, &message);
        assert!(verify(&public_key, &message, &signature));
    }

    #[test]
    fn another_message_fails() {
        let (public_key, secret_key, message) = setup();
        let signature = honest_signature(&public_key, &secret_key, &message);
        let other = &message + &message;
        assert!(!verify(&public_key, &other, &signature));
    }

    #[test]
    fn changed_function_input_fails() {
        let (public_key, secret_key, message) = setup();
        let mut signature = honest_signature(&public_key, &secret_key, &message);
        signature.function_input = &signature.function_input + &Z::ONE;
        assert!(!verify(&public_key, &message, &signature));
    }

    /// Adding a multiple of q keeps the equation over R_q but breaks
    /// the norm bound, so verification must reject.
    #[test]
    fn oversized_preimage_fails_the_norm_check() {
        let (public_key, secret_key, message) = setup();
        let mut signature = honest_signature(&public_key, &secret_key, &message);
        let mut shift = MatPolyOverZ::new(signature.preimage.get_num_rows(), 1);
        shift.set_entry(0, 0, PolyOverZ::from(10 * Q_MOD)).unwrap();
        signature.preimage = &signature.preimage + &shift;
        assert!(!verify(&public_key, &message, &signature));
    }

    #[test]
    fn oversized_randomness_fails_the_norm_check() {
        let (public_key, secret_key, message) = setup();
        let mut signature = honest_signature(&public_key, &secret_key, &message);
        let mut shift = MatPolyOverZ::new(2, 1);
        shift.set_entry(0, 0, PolyOverZ::from(Q_MOD)).unwrap();
        signature.randomness = &signature.randomness + &shift;
        assert!(!verify(&public_key, &message, &signature));
    }
}
