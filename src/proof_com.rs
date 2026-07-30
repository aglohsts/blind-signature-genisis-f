//! A Fiat-Shamir proof with rejection sampling for the commitment
//! relation `c = B_1 m + B_2 r`.
//! Report: "The Native Proof Layer".

use crate::commitment::CommitmentKey;
use crate::util::norm_inf;
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_math::traits::{
    MatrixDimensions, MatrixGetEntry, MatrixSetEntry, SetCoefficient,
};
use qfall_schemes::hash::sha256::hash_to_mat_zq_sha256;

/// The bounds used by the proof.
pub struct ProofParameters {
    pub witness_inf: i64,
    pub mask_inf: i64,
}

impl ProofParameters {
    /// The bound on the response coefficients.
    pub fn response_inf(&self, degree: i64) -> i64 {
        self.mask_inf - degree * self.witness_inf
    }
}

/// A proof of knowledge of a short opening.
pub struct Proof {
    pub challenge: PolyOverZ,
    pub message_response: MatPolyOverZ,
    pub randomness_response: MatPolyOverZ,
}

/// Proves knowledge of the opening `(m, r)` of `c`. The loop repeats
/// until the response passes the rejection step, so the response does
/// not depend on the witness.
pub fn prove(
    key: &CommitmentKey,
    parameters: &ProofParameters,
    message: &MatPolyOverZ,
    randomness: &MatPolyOverZ,
    commitment: &MatPolynomialRingZq,
) -> Proof {
    let degree = key.b1.get_mod().get_degree();
    let bound = parameters.response_inf(degree);
    assert!(bound > 0, "mask_inf must exceed degree times witness_inf");
    assert!(
        norm_inf(message, degree) <= Z::from(parameters.witness_inf)
            && norm_inf(randomness, degree) <= Z::from(parameters.witness_inf),
        "the witness coefficients exceed witness_inf",
    );
    loop {
        let message_mask = sample_mask(key.b1.get_num_columns(), degree, parameters.mask_inf);
        let randomness_mask = sample_mask(key.b2.get_num_columns(), degree, parameters.mask_inf);
        let masked = combine(key, &message_mask, &randomness_mask);
        let challenge = challenge_of(key, commitment, &masked);
        let message_response = &message_mask + &multiply(&challenge, message, degree);
        let randomness_response = &randomness_mask + &multiply(&challenge, randomness, degree);
        if norm_inf(&message_response, degree) <= Z::from(bound)
            && norm_inf(&randomness_response, degree) <= Z::from(bound)
        {
            return Proof {
                challenge,
                message_response,
                randomness_response,
            };
        }
    }
}

/// Verifies a proof for the commitment `c`.
pub fn verify(
    key: &CommitmentKey,
    parameters: &ProofParameters,
    commitment: &MatPolynomialRingZq,
    proof: &Proof,
) -> bool {
    let degree = key.b1.get_mod().get_degree();
    let bound = Z::from(parameters.response_inf(degree));
    if proof.message_response.get_num_rows() != key.b1.get_num_columns()
        || proof.randomness_response.get_num_rows() != key.b2.get_num_columns()
        || norm_inf(&proof.message_response, degree) > bound
        || norm_inf(&proof.randomness_response, degree) > bound
    {
        return false;
    }
    let modulus = key.b1.get_mod();
    let mut challenge_matrix = MatPolyOverZ::new(1, 1);
    challenge_matrix.set_entry(0, 0, &proof.challenge).unwrap();
    let challenge_ring = MatPolynomialRingZq::from((&challenge_matrix, &modulus));
    let recomputed = &combine(key, &proof.message_response, &proof.randomness_response)
        - &(&challenge_ring * commitment);
    challenge_of(key, commitment, &recomputed) == proof.challenge
}

fn sample_mask(rows: i64, degree: i64, bound: i64) -> MatPolyOverZ {
    MatPolyOverZ::sample_uniform(rows, 1, degree - 1, -bound, bound + 1).unwrap()
}

fn combine(
    key: &CommitmentKey,
    message_part: &MatPolyOverZ,
    randomness_part: &MatPolyOverZ,
) -> MatPolynomialRingZq {
    let modulus = key.b1.get_mod();
    let message_ring = MatPolynomialRingZq::from((message_part, &modulus));
    let randomness_ring = MatPolynomialRingZq::from((randomness_part, &modulus));
    &(&key.b1 * &message_ring) + &(&key.b2 * &randomness_ring)
}

/// Derives a challenge with coefficients in {-1, 0, 1}. The hash input
/// binds the matrices, the commitment, and the masking commitment.
fn challenge_of(
    key: &CommitmentKey,
    commitment: &MatPolynomialRingZq,
    masked: &MatPolynomialRingZq,
) -> PolyOverZ {
    let degree = key.b1.get_mod().get_degree();
    let input = format!("pi_com|{}|{}|{}|{}", key.b1, key.b2, commitment, masked);
    let digest = hash_to_mat_zq_sha256(&input, degree, 1, 3)
        .get_representative_least_nonnegative_residue();
    let mut challenge = PolyOverZ::default();
    for i in 0..degree {
        let value: Z = digest.get_entry(i, 0).unwrap();
        challenge.set_coeff(i, &value - Z::ONE).unwrap();
    }
    challenge
}

/// Multiplies every entry by the challenge in Z[X]/(X^d + 1).
fn multiply(challenge: &PolyOverZ, vector: &MatPolyOverZ, degree: i64) -> MatPolyOverZ {
    let mut ring_modulus = PolyOverZ::default();
    ring_modulus.set_coeff(0, 1).unwrap();
    ring_modulus.set_coeff(degree, 1).unwrap();
    let mut result = MatPolyOverZ::new(vector.get_num_rows(), 1);
    for i in 0..vector.get_num_rows() {
        let entry: PolyOverZ = vector.get_entry(i, 0).unwrap();
        let mut product = challenge * &entry;
        // reduce_by_poly underflows on the zero polynomial, which is
        // already reduced.
        if product.get_degree() >= 0 {
            product.reduce_by_poly(&ring_modulus);
        }
        result.set_entry(i, 0, product).unwrap();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfall_tools::utils::common_moduli::new_anticyclic;

    const D: i64 = 8;
    const Q: u64 = 257;

    fn setup() -> (
        CommitmentKey,
        ProofParameters,
        MatPolyOverZ,
        MatPolyOverZ,
        MatPolynomialRingZq,
    ) {
        let modulus = new_anticyclic(D, Q).unwrap();
        let key = CommitmentKey::generate(2, 2, 3, 1, &modulus);
        let parameters = ProofParameters {
            witness_inf: 20,
            mask_inf: 8000,
        };
        let message = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        let randomness = key.sample_randomness();
        let commitment = key.commit(&message, &randomness);
        (key, parameters, message, randomness, commitment)
    }

    #[test]
    fn honest_proof_verifies() {
        let (key, parameters, message, randomness, commitment) = setup();
        let proof = prove(&key, &parameters, &message, &randomness, &commitment);
        assert!(verify(&key, &parameters, &commitment, &proof));
    }

    #[test]
    fn another_commitment_fails() {
        let (key, parameters, message, randomness, commitment) = setup();
        let proof = prove(&key, &parameters, &message, &randomness, &commitment);
        let other = &commitment + &commitment;
        assert!(!verify(&key, &parameters, &other, &proof));
    }

    #[test]
    fn changed_response_fails() {
        let (key, parameters, message, randomness, commitment) = setup();
        let mut proof = prove(&key, &parameters, &message, &randomness, &commitment);
        proof.message_response = &proof.message_response + &proof.message_response;
        assert!(!verify(&key, &parameters, &commitment, &proof));
    }

    #[test]
    fn changed_challenge_fails() {
        let (key, parameters, message, randomness, commitment) = setup();
        let mut proof = prove(&key, &parameters, &message, &randomness, &commitment);
        proof.challenge.set_coeff(0, 5).unwrap();
        assert!(!verify(&key, &parameters, &commitment, &proof));
    }

    #[test]
    fn response_respects_its_bound() {
        let (key, parameters, message, randomness, commitment) = setup();
        let proof = prove(&key, &parameters, &message, &randomness, &commitment);
        let bound = Z::from(parameters.response_inf(D));
        assert!(norm_inf(&proof.message_response, D) <= bound);
        assert!(norm_inf(&proof.randomness_response, D) <= bound);
    }

    /// A zero witness makes every product with the challenge zero.
    #[test]
    fn zero_witness_is_handled() {
        let modulus = new_anticyclic(D, Q).unwrap();
        let key = CommitmentKey::generate(2, 2, 3, 1, &modulus);
        let parameters = ProofParameters {
            witness_inf: 20,
            mask_inf: 8000,
        };
        let zero = MatPolyOverZ::new(2, 1);
        let commitment = key.commit(&zero, &zero);
        let proof = prove(&key, &parameters, &zero, &zero, &commitment);
        assert!(verify(&key, &parameters, &commitment, &proof));
    }
}
