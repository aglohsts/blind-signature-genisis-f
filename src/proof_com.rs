//! Fiat-Shamir proof with aborts for the commitment relation
//! `c = B_1 * m + B_2 * r` with a short witness `(m, r)`.
//! Report: "The Proof Layer".

use crate::keys::PublicKey;
use crate::tag_function::TagFunction;
use crate::util::norm_inf;
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_math::traits::{
    GetCoefficient, MatrixDimensions, MatrixGetEntry, MatrixSetEntry, SetCoefficient,
};
use qfall_schemes::hash::sha256::hash_to_mat_zq_sha256;
use std::fmt::Write;

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
        norm_inf(m, degree) <= params.witness_inf && norm_inf(r, degree) <= params.witness_inf,
        "the witness coefficients exceed the assumed bound",
    );
    let bound = params.response_inf(degree);
    assert!(bound > 0, "mask_inf must exceed d * witness_inf");
    let (ell_m, ell_r) = (m.get_num_rows(), r.get_num_rows());
    loop {
        let y_m = MatPolyOverZ::sample_uniform(
            ell_m,
            1,
            degree - 1,
            -params.mask_inf,
            params.mask_inf + 1,
        )
        .unwrap();
        let y_r = MatPolyOverZ::sample_uniform(
            ell_r,
            1,
            degree - 1,
            -params.mask_inf,
            params.mask_inf + 1,
        )
        .unwrap();
        let t = commit_ring(pk, &y_m, &y_r);
        let gamma = challenge(pk, c, &t);
        let z_m = &y_m + &mul_scalar_negacyclic(&gamma, m, degree);
        let z_r = &y_r + &mul_scalar_negacyclic(&gamma, r, degree);
        if norm_inf(&z_m, degree) <= bound && norm_inf(&z_r, degree) <= bound {
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
    let response_inf = pk.com_params.response_inf(degree);
    if response_inf <= 0
        || c.get_num_rows() != 1
        || c.get_num_columns() != 1
        || &c.get_mod() != pk.f.modulus()
        || pk.ck.b1.get_num_rows() != 1
        || pk.ck.b2.get_num_rows() != 1
        || &pk.ck.b1.get_mod() != pk.f.modulus()
        || &pk.ck.b2.get_mod() != pk.f.modulus()
        || proof.z_m.get_num_rows() != pk.ck.b1.get_num_columns()
        || proof.z_m.get_num_columns() != 1
        || proof.z_r.get_num_rows() != pk.ck.b2.get_num_columns()
        || proof.z_r.get_num_columns() != 1
        || !entries_fit_degree(&proof.z_m, degree)
        || !entries_fit_degree(&proof.z_r, degree)
    {
        return false;
    }
    if norm_inf(&proof.z_m, degree) > response_inf || norm_inf(&proof.z_r, degree) > response_inf {
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
    let input = challenge_transcript(pk, c, t);
    let digest =
        hash_to_mat_zq_sha256(&input, degree, 1, 3).get_representative_least_nonnegative_residue();
    let mut gamma = PolyOverZ::default();
    for i in 0..degree {
        let v: Z = digest.get_entry(i, 0).unwrap();
        gamma.set_coeff(i, &v - Z::ONE).unwrap();
    }
    gamma
}

fn challenge_transcript<F: TagFunction>(
    pk: &PublicKey<F>,
    c: &MatPolynomialRingZq,
    t: &MatPolynomialRingZq,
) -> String {
    let modulus = pk.f.modulus();
    let degree = modulus.get_degree();
    let mut transcript = String::from("blind-sig/pi_com/v1");
    append_integer(&mut transcript, &modulus.get_q());
    append_polynomial(
        &mut transcript,
        &modulus.get_representative_least_nonnegative_residue(),
        degree + 1,
    );
    for matrix in [&pk.ck.b1, &pk.ck.b2, c, t] {
        append_ring_matrix(&mut transcript, matrix, degree);
    }
    transcript
}

fn append_ring_matrix(transcript: &mut String, matrix: &MatPolynomialRingZq, degree: i64) {
    append_decimal(transcript, &matrix.get_num_rows().to_string());
    append_decimal(transcript, &matrix.get_num_columns().to_string());
    let representative = matrix.get_representative_least_nonnegative_residue();
    for row in 0..matrix.get_num_rows() {
        for column in 0..matrix.get_num_columns() {
            let polynomial: PolyOverZ = representative.get_entry(row, column).unwrap();
            append_polynomial(transcript, &polynomial, degree);
        }
    }
}

fn append_polynomial(transcript: &mut String, polynomial: &PolyOverZ, length: i64) {
    for index in 0..length {
        let coefficient: Z = polynomial.get_coeff(index).unwrap();
        append_integer(transcript, &coefficient);
    }
}

fn append_integer(transcript: &mut String, value: &Z) {
    append_decimal(transcript, &value.to_string());
}

fn append_decimal(transcript: &mut String, value: &str) {
    write!(transcript, "{}:", value.len()).unwrap();
    transcript.push_str(value);
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
        // Zero is already reduced; see "The Proof Layer".
        if prod.get_degree() >= 0 {
            prod.reduce_by_poly(&ring_mod);
        }
        out.set_entry(i, 0, prod).unwrap();
    }
    out
}

fn entries_fit_degree(v: &MatPolyOverZ, degree: i64) -> bool {
    for row in 0..v.get_num_rows() {
        for column in 0..v.get_num_columns() {
            let entry: PolyOverZ = v.get_entry(row, column).unwrap();
            if entry.get_degree() >= degree {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{
        key_gen,
        tests::{toy_com_params, toy_psf},
        PublicKey,
    };
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
        let (pk, _) = key_gen(
            f,
            psf,
            2,
            2,
            Q::from(3),
            Z::from(16),
            Z::from(2000),
            toy_com_params(),
        );
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
    fn canonical_transcript_reduces_ring_coefficients() {
        let (pk, _, _, _) = setup();
        let modulus = pk.f.modulus();
        let mut low = MatPolyOverZ::new(1, 1);
        let mut high = MatPolyOverZ::new(1, 1);
        low.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
        high.set_entry(0, 0, PolyOverZ::from(258)).unwrap();
        let low = MatPolynomialRingZq::from((&low, modulus));
        let high = MatPolynomialRingZq::from((&high, modulus));
        assert_eq!(
            challenge_transcript(&pk, &low, &low),
            challenge_transcript(&pk, &high, &high),
        );
    }

    #[test]
    fn transcript_fields_are_unambiguous() {
        let mut first = String::new();
        append_decimal(&mut first, "1");
        append_decimal(&mut first, "23");
        let mut second = String::new();
        append_decimal(&mut second, "12");
        append_decimal(&mut second, "3");
        assert_ne!(first, second);
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

    #[test]
    fn response_with_wrong_shape_is_rejected() {
        let (pk, m, r, c) = setup();
        let mut proof = prove_com(&pk, &m, &r, &c);
        proof.z_m = MatPolyOverZ::new(pk.ck.b1.get_num_columns(), 2);
        assert!(!verify_com(&pk, &c, &proof));
    }

    #[test]
    fn response_outside_ring_degree_is_rejected() {
        let (pk, m, r, c) = setup();
        let mut proof = prove_com(&pk, &m, &r, &c);
        let mut entry = PolyOverZ::default();
        entry.set_coeff(D, 1).unwrap();
        proof.z_m.set_entry(0, 0, entry).unwrap();
        assert!(!verify_com(&pk, &c, &proof));
    }

    #[test]
    fn commitment_with_wrong_shape_is_rejected() {
        let (pk, m, r, c) = setup();
        let proof = prove_com(&pk, &m, &r, &c);
        let bad_c = MatPolynomialRingZq::from((&MatPolyOverZ::new(1, 2), pk.f.modulus()));
        assert!(!verify_com(&pk, &bad_c, &proof));
    }

    #[test]
    fn commitment_with_wrong_modulus_is_rejected() {
        let (pk, m, r, c) = setup();
        let proof = prove_com(&pk, &m, &r, &c);
        let modulus = qfall_tools::utils::common_moduli::new_anticyclic(D, 509).unwrap();
        let bad_c = MatPolynomialRingZq::from((&MatPolyOverZ::new(1, 1), &modulus));
        assert!(!verify_com(&pk, &bad_c, &proof));
    }

    #[test]
    fn prove_handles_zero_witness_entries() {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "proof-zero");
        let (pk, _) = key_gen(
            f,
            psf,
            2,
            2,
            Q::from(3),
            Z::from(16),
            Z::from(2000),
            toy_com_params(),
        );
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
        let bound = pk.com_params.response_inf(degree);
        assert!(norm_inf(&proof.z_m, degree) <= bound);
        assert!(norm_inf(&proof.z_r, degree) <= bound);
    }
}
