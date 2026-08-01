// report: "Key generation", implemented as described in
// "The Commitment and the Protocol Layer"
// Key generation: `pk = (A, B_1, B_2, kappa)` and `sk = T_A`.

use crate::commitment::CommitmentKey;
use crate::preimage::{Sampler, Trapdoor};
use crate::proof_com::ProofParameters;
use crate::public_function::PublicFunction;
use qfall_math::integer::Z;
use qfall_math::integer_mod_q::MatPolynomialRingZq;

// The parameters that key generation needs beyond the function.
pub struct Parameters {
    pub ell_m: i64,
    pub ell_r: i64,
    pub psi: i64,
    pub message_bound_sqrd: Z,
    pub proof: ProofParameters,
}

// The public key of the scheme.
pub struct PublicKey<F: PublicFunction> {
    pub a: MatPolynomialRingZq,
    pub commitment_key: CommitmentKey,
    pub function: F,
    pub function_key: F::Key,
    pub sampler: Sampler,
    pub message_bound_sqrd: Z,
    pub proof_parameters: ProofParameters,
}

// The secret key: the trapdoor for `A`, with the orthogonalised
// short basis that sampling reuses.
pub struct SecretKey {
    pub trapdoor: Trapdoor,
}

pub fn key_gen<F: PublicFunction>(
    function: F,
    sampler: Sampler,
    parameters: Parameters,
) -> (PublicKey<F>, SecretKey) { // runs key generation
    assert_eq!(
        sampler.modulus(),
        function.modulus(),
        "the function and the trapdoor must use the same ring modulus",
    );
    // This is where the short basis is orthogonalised, once per key.
    let (a, trapdoor) = sampler.trap_gen();
    // A width below the smoothing bound leaves every observable
    // behaviour intact and only shifts the output distribution towards
    // the secret basis, so it has to be checked here.
    assert!(
        sampler.width_meets_smoothing(&trapdoor),
        "the Gaussian width is below the smoothing bound of this basis: \
         the width is {}, the basis needs at least {:.1}. Run \
         `cargo run --release --bin parameters` at this degree and base.",
        sampler.width(),
        sampler.least_width(&trapdoor),
    );
    let commitment_key = CommitmentKey::generate(
        parameters.ell_m,
        parameters.ell_r,
        parameters.psi,
        function.rows(),
        function.modulus(),
    );
    let function_key = function.sample_key();
    let public_key = PublicKey {
        a,
        commitment_key,
        function,
        function_key,
        sampler,
        message_bound_sqrd: parameters.message_bound_sqrd,
        proof_parameters: parameters.proof,
    };
    (public_key, SecretKey { trapdoor })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::hash_to_ring::HashToRing;
    use crate::preimage::gadget_parameters;
    use qfall_math::rational::Q;
    use qfall_math::traits::MatrixDimensions;

    const D: i64 = 8;
    const Q_MOD: u64 = 257;

    pub fn toy_sampler() -> Sampler {
        Sampler::new(
            gadget_parameters(D, Q_MOD, 1),
            Q::from(100),
            Q::from(1.005_f64),
        )
    }

    pub fn toy_parameters() -> Parameters {
        Parameters {
            ell_m: 2,
            ell_r: 2,
            psi: 3,
            message_bound_sqrd: Z::from(16),
            proof: ProofParameters {
                witness_inf: 20,
                mask_inf: 8000,
            },
        }
    }

    pub fn toy_function(sampler: &Sampler, separator: &str) -> HashToRing {
        HashToRing::new(
            1,
            1u64 << 10,
            1u64 << 20,
            1u64 << 10,
            sampler.modulus().clone(),
            separator,
        )
    }

    fn setup() -> (PublicKey<HashToRing>, SecretKey) {
        let sampler = toy_sampler();
        let function = toy_function(&sampler, "keys-test");
        key_gen(function, sampler, toy_parameters())
    }

    #[test]
    fn public_key_dimensions() {
        let (public_key, _) = setup();
        assert_eq!(1, public_key.a.get_num_rows());
        assert!(public_key.a.get_num_columns() > 1);
        assert_eq!(&public_key.a.get_mod(), public_key.function.modulus());
    }

    // the function key is fixed by the public key, so it stays the
    // same for every session
    #[test]
    fn function_key_is_inside_its_space() {
        let (public_key, _) = setup();
        let value = public_key
            .function
            .eval(&public_key.function_key, &Z::from(5), &Z::from(7));
        assert_eq!(1, value.get_num_rows());
    }

    #[test]
    fn trapdoor_samples_valid_preimages() {
        let (public_key, secret_key) = setup();
        let target = MatPolynomialRingZq::sample_uniform(1, 1, public_key.function.modulus());
        let preimage = public_key.sampler.samp_p(&secret_key.trapdoor, &target);
        assert_eq!(target, public_key.sampler.f_a(&public_key.a, &preimage));
        assert!(public_key.sampler.check_domain(&preimage));
    }

    // report: "A Parameter That Was Silently Wrong"
    // a key whose sampler leaks towards the trapdoor cannot be built
    #[test]
    #[should_panic(expected = "below the smoothing bound")]
    fn a_width_below_the_smoothing_bound_is_rejected() {
        let sampler = Sampler::new(
            gadget_parameters(D, Q_MOD, 1),
            Q::from(1),
            Q::from(1.005_f64),
        );
        let function = toy_function(&sampler, "smoothing-test");
        key_gen(function, sampler, toy_parameters());
    }

    #[test]
    #[should_panic(expected = "same ring modulus")]
    fn modulus_mismatch_is_rejected() {
        let sampler = toy_sampler();
        let other = qfall_tools::utils::common_moduli::new_anticyclic(D, 509).unwrap();
        let function = HashToRing::new(1, 1u64 << 10, 1u64 << 20, 1u64 << 10, other, "keys-test");
        key_gen(function, sampler, toy_parameters());
    }
}
