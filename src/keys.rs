//! Key generation: `pk = (A, B_1, B_2, f, N)`, `sk = T_A`.
//! Report: "The Commitment and the Protocol Layer".

use crate::commitment::CommitmentKey;
use crate::proof_com::ComProofParams;
use crate::tag_function::TagFunction;
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_math::rational::Q;
use qfall_tools::primitive::psf::{PSF, PSFGPVRing};

/// The public key of the scheme.
pub struct PublicKey<F: TagFunction> {
    pub a: MatPolynomialRingZq,
    pub ck: CommitmentKey,
    pub f: F,
    pub psf: PSFGPVRing,
    pub s_r: Q,
    pub beta_msg_sqrd: Z,
    pub beta_r_sqrd: Z,
    pub com_params: ComProofParams,
}

/// The secret key: the trapdoor `T_A` for `A`.
pub struct SecretKey {
    pub trapdoor: (MatPolyOverZ, MatPolyOverZ),
}

/// Runs key generation; panics if the moduli of `f` and the trapdoor
/// parameters differ, or if `f` does not have module rank 1.
pub fn key_gen<F: TagFunction>(
    f: F,
    psf: PSFGPVRing,
    ell_m: i64,
    ell_r: i64,
    s_r: Q,
    beta_msg_sqrd: Z,
    beta_r_sqrd: Z,
    com_params: ComProofParams,
) -> (PublicKey<F>, SecretKey) {
    assert_eq!(
        &psf.gp.modulus,
        f.modulus(),
        "the tag function and the trapdoor must use the same ring modulus",
    );
    assert_eq!(
        1,
        f.rows(),
        "the ring-setting prototype supports module rank n = 1 only",
    );
    let (a, trapdoor) = psf.trap_gen();
    let ck = CommitmentKey::generate(ell_m, ell_r, f.modulus());
    (
        PublicKey {
            a,
            ck,
            f,
            psf,
            s_r,
            beta_msg_sqrd,
            beta_r_sqrd,
            com_params,
        },
        SecretKey { trapdoor },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tag_function::HashToRing;
    use qfall_math::traits::MatrixDimensions;
    use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;

    const D: i64 = 8;
    const Q_MOD: u64 = 257;

    pub(crate) fn toy_com_params() -> ComProofParams {
        ComProofParams {
            witness_inf: 20,
            mask_inf: 8000,
        }
    }

    pub(crate) fn toy_psf() -> PSFGPVRing {
        PSFGPVRing {
            gp: GadgetParametersRing::init_default(D, Q_MOD),
            s: Q::from(100),
            s_td: Q::from(1.005_f64),
        }
    }

    fn setup() -> (PublicKey<HashToRing>, SecretKey) {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "keys-test");
        key_gen(f, psf, 2, 2, Q::from(3), Z::from(16), Z::from(300), toy_com_params())
    }

    #[test]
    fn public_key_dimensions() {
        let (pk, _) = setup();
        assert_eq!(1, pk.a.get_num_rows());
        assert!(pk.a.get_num_columns() > 1);
        assert_eq!(&pk.a.get_mod(), pk.f.modulus());
    }

    #[test]
    fn trapdoor_samples_valid_preimages() {
        let (pk, sk) = setup();
        let target = MatPolynomialRingZq::sample_uniform(1, 1, pk.f.modulus());
        let s = pk.psf.samp_p(&pk.a, &sk.trapdoor, &target);
        assert_eq!(target, pk.psf.f_a(&pk.a, &s));
        assert!(pk.psf.check_domain(&s));
    }

    #[test]
    #[should_panic(expected = "same ring modulus")]
    fn modulus_mismatch_rejected() {
        let psf = toy_psf();
        let other_modulus = qfall_tools::utils::common_moduli::new_anticyclic(D, 509).unwrap();
        let f = HashToRing::new(1, 1u64 << 20, other_modulus, "keys-test");
        key_gen(f, psf, 2, 2, Q::from(3), Z::from(16), Z::from(300), toy_com_params());
    }
}
