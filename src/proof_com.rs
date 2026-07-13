//! Fiat-Shamir proof with aborts for the commitment relation
//! `c = B_1 * m + B_2 * r` with a short witness `(m, r)`.
//! Report: "The Proof Layer".

use crate::keys::PublicKey;
use crate::tag_function::TagFunction;
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_math::traits::{
    IntoCoefficientEmbedding, MatrixDimensions, MatrixGetEntry, MatrixSetEntry,
    SetCoefficient,
};
use qfall_schemes::hash::sha256::hash_to_mat_zq_sha256;

/// Parameters of the proof: the assumed bound on the witness
/// coefficients and the bound on the masking coefficients.
pub struct ComProofParams {
    pub witness_inf: i64,
    pub mask_inf: i64,
}

impl ComProofParams {
    /// The bound `T = d * witness_inf` on the coefficients of
    /// `challenge * witness`.
    fn shift_inf(&self, degree: i64) -> i64 {
        degree * self.witness_inf
    }

    /// The bound on the response coefficients, `mask_inf - T`.
    pub fn response_inf(&self, degree: i64) -> i64 {
        self.mask_inf - self.shift_inf(degree)
    }
}

/// The proof: a ternary challenge and the masked witness.
pub struct ComProof {
    pub challenge: PolyOverZ,
    pub z_m: MatPolyOverZ,
    pub z_r: MatPolyOverZ,
}

/// Proves knowledge of a short opening `(m, r)` of the commitment `c`.
/// Repeats until the rejection step accepts.
pub fn prove_com<F: TagFunction>(
    pk: &PublicKey<F>,
    m: &MatPolyOverZ,
    r: &MatPolyOverZ,
    c: &MatPolynomialRingZq,
) -> ComProof {
    let degree = pk.f.modulus().get_degree();
    let params = &pk.com_params;
    assert!(
        norm_inf(m, degree) <= Z::from(params.witness_inf)
            && norm_inf(r, degree) <= Z::from(params.witness_inf),
        "the witness coefficients exceed the assumed bound",
    );
    let bound = params.response_inf(degree);
    assert!(bound > 0, "mask_inf must exceed d * witness_inf");
    let (ell_m, ell_r) = (m.get_num_rows(), r.get_num_rows());
    loop {
        let y_m =
            MatPolyOverZ::sample_uniform(ell_m, 1, degree - 1, -params.mask_inf, params.mask_inf + 1)
                .unwrap();
        let y_r =
            MatPolyOverZ::sample_uniform(ell_r, 1, degree - 1, -params.mask_inf, params.mask_inf + 1)
                .unwrap();
        let t = commit_ring(pk, &y_m, &y_r);
        let gamma = challenge(pk, c, &t);
        let z_m = &y_m + &mul_scalar_negacyclic(&gamma, m, degree);
        let z_r = &y_r + &mul_scalar_negacyclic(&gamma, r, degree);
        if norm_inf(&z_m, degree) <= Z::from(bound) && norm_inf(&z_r, degree) <= Z::from(bound) {
            return ComProof {
                challenge: gamma,
                z_m,
                z_r,
            };
        }
    }
}

/// Verifies a proof for the commitment `c`.
pub fn verify_com<F: TagFunction>(
    pk: &PublicKey<F>,
    c: &MatPolynomialRingZq,
    proof: &ComProof,
) -> bool {
    let degree = pk.f.modulus().get_degree();
    let bound = Z::from(pk.com_params.response_inf(degree));
    if proof.z_m.get_num_rows() != pk.ck.b1.get_num_columns()
        || proof.z_r.get_num_rows() != pk.ck.b2.get_num_columns()
        || norm_inf(&proof.z_m, degree) > bound
        || norm_inf(&proof.z_r, degree) > bound
    {
        return false;
    }
    // t' = B_1 * z_m + B_2 * z_r - challenge * c.
    let modulus = pk.f.modulus();
    let mut gamma_mat = MatPolyOverZ::new(1, 1);
    gamma_mat.set_entry(0, 0, &proof.challenge).unwrap();
    let gamma_ring = MatPolynomialRingZq::from((&gamma_mat, modulus));
    let t = &commit_ring(pk, &proof.z_m, &proof.z_r) - &(&gamma_ring * c);
    challenge(pk, c, &t) == proof.challenge
}

fn commit_ring<F: TagFunction>(
    pk: &PublicKey<F>,
    v_m: &MatPolyOverZ,
    v_r: &MatPolyOverZ,
) -> MatPolynomialRingZq {
    let modulus = pk.f.modulus();
    let v_m_ring = MatPolynomialRingZq::from((v_m, modulus));
    let v_r_ring = MatPolynomialRingZq::from((v_r, modulus));
    &(&pk.ck.b1 * &v_m_ring) + &(&pk.ck.b2 * &v_r_ring)
}

/// Derives a ternary challenge from the statement and the masking
/// commitment; the hash input binds `B_1`, `B_2`, `c` and `t`.
fn challenge<F: TagFunction>(
    pk: &PublicKey<F>,
    c: &MatPolynomialRingZq,
    t: &MatPolynomialRingZq,
) -> PolyOverZ {
    let degree = pk.f.modulus().get_degree();
    let input = format!("pi_com|{}|{}|{}|{}", pk.ck.b1, pk.ck.b2, c, t);
    let digest = hash_to_mat_zq_sha256(&input, degree, 1, 3).get_representative_least_nonnegative_residue();
    let mut gamma = PolyOverZ::default();
    for i in 0..degree {
        let v: Z = digest.get_entry(i, 0).unwrap();
        gamma.set_coeff(i, &v - Z::ONE).unwrap();
    }
    gamma
}

/// Multiplies every entry of `v` by `gamma` in `Z[X]/(X^d + 1)`.
fn mul_scalar_negacyclic(gamma: &PolyOverZ, v: &MatPolyOverZ, degree: i64) -> MatPolyOverZ {
    let mut ring_mod = PolyOverZ::default();
    ring_mod.set_coeff(0, 1).unwrap();
    ring_mod.set_coeff(degree, 1).unwrap();
    let mut out = MatPolyOverZ::new(v.get_num_rows(), 1);
    for i in 0..v.get_num_rows() {
        let entry: PolyOverZ = v.get_entry(i, 0).unwrap();
        let mut prod = gamma * &entry;
        // qfall's reduce_by_poly underflows on the zero polynomial,
        // which occurs when gamma or the entry is zero. A zero product
        // is already reduced. Report: "The Proof Layer".
        if prod.get_degree() >= 0 {
            prod.reduce_by_poly(&ring_mod);
        }
        out.set_entry(i, 0, prod).unwrap();
    }
    out
}

fn norm_inf(v: &MatPolyOverZ, degree: i64) -> Z {
    v.clone()
        .into_coefficient_embedding(degree)
        .norm_l_infty_infty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{PublicKey, key_gen, tests::{toy_com_params, toy_psf}};
    use crate::tag_function::HashToRing;
    use qfall_math::rational::Q;

    const D: i64 = 8;

    fn setup() -> (
        PublicKey<HashToRing>,
        MatPolyOverZ,
        MatPolyOverZ,
        MatPolynomialRingZq,
    ) {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "proof-test");
        let (pk, _) = key_gen(f, psf, 2, 2, Q::from(3), Z::from(16), Z::from(2000), toy_com_params());
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let r = pk.ck.sample_randomness(&pk.s_r);
        let c = pk.ck.commit(&m, &r);
        (pk, m, r, c)
    }

    #[test]
    fn honest_proof_verifies() {
        let (pk, m, r, c) = setup();
        let proof = prove_com(&pk, &m, &r, &c);
        assert!(verify_com(&pk, &c, &proof));
    }

    #[test]
    fn proof_fails_for_a_different_commitment() {
        let (pk, m, r, c) = setup();
        let proof = prove_com(&pk, &m, &r, &c);
        let other_c = &c + &c;
        assert!(!verify_com(&pk, &other_c, &proof));
    }

    #[test]
    fn tampered_response_fails() {
        let (pk, m, r, c) = setup();
        let mut proof = prove_com(&pk, &m, &r, &c);
        proof.z_m = &proof.z_m + &proof.z_m;
        assert!(!verify_com(&pk, &c, &proof));
    }

    #[test]
    fn tampered_challenge_fails() {
        let (pk, m, r, c) = setup();
        let mut proof = prove_com(&pk, &m, &r, &c);
        proof.challenge.set_coeff(0, 5).unwrap();
        assert!(!verify_com(&pk, &c, &proof));
    }

    // Regression: a zero witness entry makes gamma * entry the zero
    // polynomial, which used to underflow inside qfall's reduce_by_poly.
    #[test]
    fn prove_handles_zero_witness_entries() {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "proof-zero");
        let (pk, _) = key_gen(f, psf, 2, 2, Q::from(3), Z::from(16), Z::from(2000), toy_com_params());
        let zero_m = MatPolyOverZ::new(2, 1);
        let zero_r = MatPolyOverZ::new(2, 1);
        let c = pk.ck.commit(&zero_m, &zero_r);
        let proof = prove_com(&pk, &zero_m, &zero_r, &c);
        assert!(verify_com(&pk, &c, &proof));
    }

    #[test]
    fn response_bound_is_enforced() {
        let (pk, m, r, c) = setup();
        let proof = prove_com(&pk, &m, &r, &c);
        let degree = pk.f.modulus().get_degree();
        let bound = Z::from(pk.com_params.response_inf(degree));
        assert!(norm_inf(&proof.z_m, degree) <= bound);
        assert!(norm_inf(&proof.z_r, degree) <= bound);
    }
}
