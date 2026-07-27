//! Key generation: `pk = (A, B_1, B_2, kappa)` and `sk = T_A`.
//! Report: "Key generation".

use crate::commitment::CommitmentKey;
use crate::hash_to_ring::HashToRing;
use crate::proof_com::ProofParameters;
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_tools::primitive::psf::{PSF, PSFGPVRing};

/// The parameters that key generation needs beyond the function.
pub struct Parameters {
    pub ell_m: i64,
    pub ell_r: i64,
    pub psi: i64,
    pub message_bound_sqrd: Z,
    pub proof: ProofParameters,
}

/// The public key of the scheme.
pub struct PublicKey {
    pub a: MatPolynomialRingZq,
    pub commitment_key: CommitmentKey,
    pub function: HashToRing,
    pub function_key: Z,
    pub psf: PSFGPVRing,
    pub message_bound_sqrd: Z,
    pub proof_parameters: ProofParameters,
}

/// The secret key: the trapdoor for `A`.
pub struct SecretKey {
    pub trapdoor: (MatPolyOverZ, MatPolyOverZ),
}

/// Runs key generation.
pub fn key_gen(
    function: HashToRing,
    psf: PSFGPVRing,
    parameters: Parameters,
) -> (PublicKey, SecretKey) {
    assert_eq!(
        &psf.gp.modulus,
        function.modulus(),
        "the function and the trapdoor must use the same ring modulus",
    );
    let (a, trapdoor) = psf.trap_gen();
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
        psf,
        message_bound_sqrd: parameters.message_bound_sqrd,
        proof_parameters: parameters.proof,
    };
    (public_key, SecretKey { trapdoor })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use qfall_math::rational::Q;
    use qfall_math::traits::MatrixDimensions;
    use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;

    const D: i64 = 8;
    const Q_MOD: u64 = 257;

    pub fn toy_psf() -> PSFGPVRing {
        PSFGPVRing {
            gp: GadgetParametersRing::init_default(D, Q_MOD),
            s: Q::from(100),
            s_td: Q::from(1.005_f64),
        }
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

    pub fn toy_function(psf: &PSFGPVRing, separator: &str) -> HashToRing {
        HashToRing::new(
            1,
            1u64 << 10,
            1u64 << 20,
            1u64 << 10,
            psf.gp.modulus.clone(),
            separator,
        )
    }

    fn setup() -> (PublicKey, SecretKey) {
        let psf = toy_psf();
        let function = toy_function(&psf, "keys-test");
        key_gen(function, psf, toy_parameters())
    }

    #[test]
    fn public_key_dimensions() {
        let (public_key, _) = setup();
        assert_eq!(1, public_key.a.get_num_rows());
        assert!(public_key.a.get_num_columns() > 1);
        assert_eq!(&public_key.a.get_mod(), public_key.function.modulus());
    }

    /// The function key is fixed by the public key, so it stays the
    /// same for every session.
    #[test]
    fn function_key_is_inside_its_space() {
        let (public_key, _) = setup();
        let value = public_key
            .function
            .eval(&public_key.function_key, &Z::from(5), &Z::from(7));
        assert_eq!(1, value.get_num_rows());
    }

    /// The trapdoor produces preimages that satisfy the relation and
    /// the norm bound of the sampler.
    #[test]
    fn trapdoor_samples_valid_preimages() {
        let (public_key, secret_key) = setup();
        let target = MatPolynomialRingZq::sample_uniform(1, 1, public_key.function.modulus());
        let preimage = public_key
            .psf
            .samp_p(&public_key.a, &secret_key.trapdoor, &target);
        assert_eq!(target, public_key.psf.f_a(&public_key.a, &preimage));
        assert!(public_key.psf.check_domain(&preimage));
    }

    #[test]
    #[should_panic(expected = "same ring modulus")]
    fn modulus_mismatch_is_rejected() {
        let psf = toy_psf();
        let other = qfall_tools::utils::common_moduli::new_anticyclic(D, 509).unwrap();
        let function = HashToRing::new(1, 1u64 << 10, 1u64 << 20, 1u64 << 10, other, "keys-test");
        key_gen(function, psf, toy_parameters());
    }
}
