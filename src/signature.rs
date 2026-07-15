//! Final-signature relations and the transparent pi_sig placeholder.
//! Report: "The Final-Signature Proof".

use crate::issue::{SignerResponse, UserState};
use crate::keys::PublicKey;
use crate::tag_function::{BinaryEncoding, TagFunction};
use crate::util::norm_eucl_sqrd;
use qfall_math::integer::{MatPolyOverZ, MatZ, PolyOverZ, Z};
use qfall_math::traits::{MatrixDimensions, MatrixGetEntry};
use qfall_tools::primitive::psf::PSF;

/// The hidden witness for the binary final-signature relation.
pub struct BinarySignatureWitness {
    pub tag_encoding: MatZ,
    pub s: MatPolyOverZ,
    pub r: MatPolyOverZ,
}

/// Checks the binary final-signature relation without producing a proof.
pub fn binary_relation_holds(
    pk: &PublicKey<BinaryEncoding>,
    m: &MatPolyOverZ,
    witness: &BinarySignatureWitness,
) -> bool {
    let degree = pk.f.modulus().get_degree();
    if (m.get_num_rows(), m.get_num_columns()) != (pk.ck.b1.get_num_columns(), 1)
        || (witness.r.get_num_rows(), witness.r.get_num_columns())
            != (pk.ck.b2.get_num_columns(), 1)
        || (witness.s.get_num_rows(), witness.s.get_num_columns()) != (pk.a.get_num_columns(), 1)
        || !fits_ring_degree(m, degree)
        || !fits_ring_degree(&witness.r, degree)
        || !fits_ring_degree(&witness.s, degree)
    {
        return false;
    }
    let Some(tag_image) = pk.f.eval_encoding(&witness.tag_encoding) else {
        return false;
    };

    norm_eucl_sqrd(&witness.s, degree) > Z::ZERO
        && pk.psf.check_domain(&witness.s)
        && norm_eucl_sqrd(m, degree) <= pk.beta_msg_sqrd
        && norm_eucl_sqrd(&witness.r, degree) <= pk.beta_r_sqrd
        && pk.psf.f_a(&pk.a, &witness.s) == tag_image + pk.ck.commit(m, &witness.r)
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

/// A transparent signature: the witness of the signing relation.
pub struct TransparentSignature {
    pub x: Z,
    pub s: MatPolyOverZ,
    pub r: MatPolyOverZ,
}

/// Step 4: assembles the signature; the caller runs the user check
/// first.
pub fn finalize(st: UserState, resp: SignerResponse) -> TransparentSignature {
    TransparentSignature {
        x: resp.x,
        s: resp.s,
        r: st.r,
    }
}

/// Verifies the signing relation directly.
pub fn verify<F: TagFunction>(
    pk: &PublicKey<F>,
    m: &MatPolyOverZ,
    sig: &TransparentSignature,
) -> bool {
    let degree = pk.f.modulus().get_degree();
    // The norm bounds come first: the reused f_a asserts its domain
    // bound internally. Report: "The Commitment and the Protocol
    // Layer".
    sig.x >= Z::ONE
        && sig.x <= pk.f.domain_size()
        && pk.psf.check_domain(&sig.s)
        && norm_eucl_sqrd(m, degree) <= pk.beta_msg_sqrd
        && norm_eucl_sqrd(&sig.r, degree) <= pk.beta_r_sqrd
        && pk.psf.f_a(&pk.a, &sig.s) == &pk.f.eval(&sig.x) + &pk.ck.commit(m, &sig.r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issue::{signer_respond, user_check, user_commit};
    use crate::keys::{
        key_gen,
        tests::{toy_key_gen_params, toy_psf},
        PublicKey, SecretKey,
    };
    use crate::tag_function::{BinaryEncoding, HashToRing};
    use qfall_math::integer::PolyOverZ;
    use qfall_math::traits::{MatrixSetEntry, SetCoefficient};

    const D: i64 = 8;
    const Q_MOD: u64 = 257;

    fn setup() -> (PublicKey<HashToRing>, SecretKey, MatPolyOverZ) {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "sig-test");
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        (pk, sk, m)
    }

    fn honest_signature(
        pk: &PublicKey<HashToRing>,
        sk: &SecretKey,
        m: &MatPolyOverZ,
    ) -> TransparentSignature {
        let (msg, st) = user_commit(pk, m);
        let resp = signer_respond(pk, sk, &msg).expect("signer aborted");
        assert!(user_check(pk, &st, &resp));
        finalize(st, resp)
    }

    #[test]
    fn honest_binary_relation_holds() {
        let psf = toy_psf();
        let f = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        assert!(user_check(&pk, &st, &resp));
        let witness = BinarySignatureWitness {
            tag_encoding: pk.f.encode_tag(&resp.x),
            s: resp.s,
            r: st.r,
        };
        assert!(binary_relation_holds(&pk, &m, &witness));
    }

    #[test]
    fn non_binary_tag_witness_is_rejected() {
        let psf = toy_psf();
        let f = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        let mut tag_encoding = pk.f.encode_tag(&resp.x);
        tag_encoding.set_entry(0, 0, 2).unwrap();
        let witness = BinarySignatureWitness {
            tag_encoding,
            s: resp.s,
            r: st.r,
        };
        assert!(!binary_relation_holds(&pk, &m, &witness));
    }

    #[test]
    fn binary_relation_is_bound_to_the_public_message() {
        let psf = toy_psf();
        let f = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        let witness = BinarySignatureWitness {
            tag_encoding: pk.f.encode_tag(&resp.x),
            s: resp.s,
            r: st.r,
        };
        let mut delta = MatPolyOverZ::new(2, 1);
        delta.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
        assert!(!binary_relation_holds(&pk, &(&m + &delta), &witness));
    }

    #[test]
    fn malformed_binary_witness_dimensions_are_rejected() {
        let psf = toy_psf();
        let f = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        let tag_encoding = pk.f.encode_tag(&resp.x);

        let bad_tag = BinarySignatureWitness {
            tag_encoding: MatZ::new(10, 2),
            s: resp.s.clone(),
            r: st.r.clone(),
        };
        assert!(!binary_relation_holds(&pk, &m, &bad_tag));

        let bad_s = BinarySignatureWitness {
            tag_encoding: tag_encoding.clone(),
            s: MatPolyOverZ::new(pk.a.get_num_columns(), 2),
            r: st.r.clone(),
        };
        assert!(!binary_relation_holds(&pk, &m, &bad_s));

        let bad_r = BinarySignatureWitness {
            tag_encoding,
            s: resp.s,
            r: MatPolyOverZ::new(pk.ck.b2.get_num_columns() + 1, 1),
        };
        assert!(!binary_relation_holds(&pk, &m, &bad_r));
    }

    #[test]
    fn binary_relation_rejects_polynomials_outside_ring_degree() {
        let psf = toy_psf();
        let f = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        let tag_encoding = pk.f.encode_tag(&resp.x);
        let mut high_degree = PolyOverZ::default();
        high_degree.set_coeff(D, 1).unwrap();

        let mut bad_m = m.clone();
        bad_m.set_entry(0, 0, high_degree.clone()).unwrap();
        let honest_witness = BinarySignatureWitness {
            tag_encoding: tag_encoding.clone(),
            s: resp.s.clone(),
            r: st.r.clone(),
        };
        assert!(!binary_relation_holds(&pk, &bad_m, &honest_witness));

        let mut bad_s = resp.s.clone();
        bad_s.set_entry(0, 0, high_degree.clone()).unwrap();
        let bad_s_witness = BinarySignatureWitness {
            tag_encoding: tag_encoding.clone(),
            s: bad_s,
            r: st.r.clone(),
        };
        assert!(!binary_relation_holds(&pk, &m, &bad_s_witness));

        let mut bad_r = st.r;
        bad_r.set_entry(0, 0, high_degree).unwrap();
        let bad_r_witness = BinarySignatureWitness {
            tag_encoding,
            s: resp.s,
            r: bad_r,
        };
        assert!(!binary_relation_holds(&pk, &m, &bad_r_witness));
    }

    #[test]
    fn binary_relation_enforces_the_public_message_bound() {
        let psf = toy_psf();
        let f = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        let witness = BinarySignatureWitness {
            tag_encoding: pk.f.encode_tag(&resp.x),
            s: resp.s,
            r: st.r,
        };
        let mut shift = MatPolyOverZ::new(2, 1);
        shift.set_entry(0, 0, PolyOverZ::from(Q_MOD)).unwrap();
        let oversized_m = &m + &shift;
        let tag_image = pk.f.eval_encoding(&witness.tag_encoding).unwrap();
        assert_eq!(
            pk.psf.f_a(&pk.a, &witness.s),
            tag_image + pk.ck.commit(&oversized_m, &witness.r),
        );
        assert!(!binary_relation_holds(&pk, &oversized_m, &witness));
    }

    #[test]
    fn honest_signature_verifies() {
        let (pk, sk, m) = setup();
        let sig = honest_signature(&pk, &sk, &m);
        assert!(verify(&pk, &m, &sig));
    }

    #[test]
    fn different_message_fails() {
        let (pk, sk, m) = setup();
        let sig = honest_signature(&pk, &sk, &m);
        let other_m = &m + &m;
        assert!(!verify(&pk, &other_m, &sig));
    }

    #[test]
    fn tampered_tag_fails() {
        let (pk, sk, m) = setup();
        let mut sig = honest_signature(&pk, &sk, &m);
        sig.x = &sig.x + &Z::ONE;
        assert!(!verify(&pk, &m, &sig));
    }

    // Shifting one coefficient by a multiple of q keeps the equation
    // valid over R_q but breaks the norm bound.
    #[test]
    fn oversized_preimage_fails_norm_check() {
        let (pk, sk, m) = setup();
        let mut sig = honest_signature(&pk, &sk, &m);
        let mut shift = MatPolyOverZ::new(
            qfall_math::traits::MatrixDimensions::get_num_rows(&sig.s),
            1,
        );
        shift.set_entry(0, 0, PolyOverZ::from(10 * Q_MOD)).unwrap();
        sig.s = &sig.s + &shift;
        let modulus = pk.f.modulus();
        let s_ring = qfall_math::integer_mod_q::MatPolynomialRingZq::from((&sig.s, modulus));
        assert!(
            &pk.a * &s_ring == &pk.f.eval(&sig.x) + &pk.ck.commit(&m, &sig.r),
            "the equation must still hold over R_q",
        );
        assert!(!verify(&pk, &m, &sig));
    }

    #[test]
    fn oversized_randomness_fails_norm_check() {
        let (pk, sk, m) = setup();
        let mut sig = honest_signature(&pk, &sk, &m);
        let mut shift = MatPolyOverZ::new(2, 1);
        shift.set_entry(0, 0, PolyOverZ::from(Q_MOD)).unwrap();
        sig.r = &sig.r + &shift;
        assert!(!verify(&pk, &m, &sig));
    }
}
