//! Finalisation and verification.
//! Report: "Finalisation", "Verification", and "The Final-Signature
//! Proof".
//!
//! Two paths exist. The transparent signature carries the witness in
//! the clear and gives no blindness; it is kept because it works for
//! every public function, including the hash-based one. The
//! proof-based path replaces the witness by `pi_sig` and needs a
//! function whose evaluation is linear in its hidden arguments.

use crate::issue::{Response, UserState};
use crate::keys::PublicKey;
use crate::module_lwe::ModuleLweEncoding;
use crate::public_function::PublicFunction;
use crate::util::norm_eucl_sqrd;
use qfall_math::integer::{MatPolyOverZ, MatZ, PolyOverZ, Z};
use qfall_math::traits::{MatrixDimensions, MatrixGetEntry};
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

/// A proof provider for the final-signature relation `R_sig`.
pub trait FinalSignatureProofProvider<F: PublicFunction> {
    type Witness;
    type Proof;
    type Error;

    fn prove(
        &self,
        public_key: &PublicKey<F>,
        message: &MatPolyOverZ,
        witness: &Self::Witness,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify(
        &self,
        public_key: &PublicKey<F>,
        message: &MatPolyOverZ,
        proof: &Self::Proof,
    ) -> bool;
}

/// The hidden witness of `R_sig` for the algebraic public function.
/// The function input `mu` appears only through its binary encoding,
/// which is the form the proof system can handle.
pub struct ModuleLweWitness {
    pub encoding: MatZ,
    pub function_randomness: MatPolyOverZ,
    pub preimage: MatPolyOverZ,
    pub randomness: MatPolyOverZ,
}

/// A final signature that contains only its proof.
pub struct ProofSignature<P> {
    pub proof: P,
}

/// Builds the hidden witness from an accepted issuing run.
pub fn signature_witness(
    public_key: &PublicKey<ModuleLweEncoding>,
    state: UserState,
    response: Response<ModuleLweEncoding>,
) -> ModuleLweWitness {
    ModuleLweWitness {
        encoding: public_key.function.encode(&response.function_input),
        function_randomness: response.function_randomness,
        preimage: response.preimage,
        randomness: state.randomness,
    }
}

/// Step 4 of the proof-based path: assembles a signature that hides
/// the witness.
pub fn finalise_with_provider<P>(
    public_key: &PublicKey<ModuleLweEncoding>,
    state: UserState,
    response: Response<ModuleLweEncoding>,
    provider: &P,
) -> Result<ProofSignature<P::Proof>, P::Error>
where
    P: FinalSignatureProofProvider<ModuleLweEncoding, Witness = ModuleLweWitness>,
{
    let message = state.message.clone();
    let witness = signature_witness(public_key, state, response);
    provider
        .prove(public_key, &message, &witness)
        .map(|proof| ProofSignature { proof })
}

/// Verifies a proof-based signature against its public message.
pub fn verify_with_provider<P>(
    public_key: &PublicKey<ModuleLweEncoding>,
    message: &MatPolyOverZ,
    signature: &ProofSignature<P::Proof>,
    provider: &P,
) -> bool
where
    P: FinalSignatureProofProvider<ModuleLweEncoding>,
{
    provider.verify(public_key, message, &signature.proof)
}

/// Checks `R_sig` on the witness without producing a proof. The proof
/// provider calls this before it hands the witness to LaZer, so a
/// malformed witness is reported as an error instead of an invalid
/// proof.
pub fn relation_holds(
    public_key: &PublicKey<ModuleLweEncoding>,
    message: &MatPolyOverZ,
    witness: &ModuleLweWitness,
) -> bool {
    let function = &public_key.function;
    let degree = function.modulus().get_degree();
    if (message.get_num_rows(), message.get_num_columns())
        != (public_key.commitment_key.b1.get_num_columns(), 1)
        || (witness.randomness.get_num_rows(), witness.randomness.get_num_columns())
            != (public_key.commitment_key.b2.get_num_columns(), 1)
        || (witness.preimage.get_num_rows(), witness.preimage.get_num_columns())
            != (public_key.a.get_num_columns(), 1)
        || !fits_ring_degree(message, degree)
        || !fits_ring_degree(&witness.randomness, degree)
        || !fits_ring_degree(&witness.preimage, degree)
        || !fits_ring_degree(&witness.function_randomness, degree)
        || !is_binary(&witness.encoding)
    {
        return false;
    }
    let Some(encoding_image) = function.eval_encoding(&witness.encoding) else {
        return false;
    };
    if !function.contains_randomness(&witness.function_randomness) {
        return false;
    }
    let masking = &public_key.function_key
        * &qfall_math::integer_mod_q::MatPolynomialRingZq::from((
            &witness.function_randomness,
            function.modulus(),
        ));

    norm_eucl_sqrd(&witness.preimage, degree) > Z::ZERO
        && public_key.psf.check_domain(&witness.preimage)
        && norm_eucl_sqrd(message, degree) <= public_key.message_bound_sqrd
        && norm_eucl_sqrd(&witness.randomness, degree)
            <= public_key.commitment_key.randomness_bound_sqrd()
        && norm_eucl_sqrd(&witness.function_randomness, degree)
            <= function.randomness_bound_sqrd()
        && public_key.psf.f_a(&public_key.a, &witness.preimage)
            == &(&masking + &encoding_image)
                + &public_key
                    .commitment_key
                    .commit(message, &witness.randomness)
}

fn fits_ring_degree(vector: &MatPolyOverZ, degree: i64) -> bool {
    for row in 0..vector.get_num_rows() {
        for column in 0..vector.get_num_columns() {
            let polynomial: PolyOverZ = vector.get_entry(row, column).unwrap();
            if polynomial.get_degree() >= degree {
                return false;
            }
        }
    }
    true
}

fn is_binary(encoding: &MatZ) -> bool {
    for row in 0..encoding.get_num_rows() {
        let bit: Z = encoding.get_entry(row, 0).unwrap();
        if bit != Z::ZERO && bit != Z::ONE {
            return false;
        }
    }
    true
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
    use qfall_math::traits::MatrixSetEntry;

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
