// report: "The Commitment and the Protocol Layer"
// commitment `c = B_1 m + B_2 r` over `R_q`.

use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};
use qfall_math::traits::MatrixDimensions;

// public commitment matrices.
pub struct CommitmentKey {
    pub b1: MatPolynomialRingZq,
    pub b2: MatPolynomialRingZq,
    pub psi: i64,
}

impl CommitmentKey {
    pub fn generate(
        ell_m: i64,
        ell_r: i64,
        psi: i64,
        rows: i64,
        modulus: &ModulusPolynomialRingZq,
    ) -> CommitmentKey { // sample uniform `B_1` and `B_2`; `psi` fixes the randomness distribution `chi_r`
        assert!(ell_m >= 1, "the message length must be at least 1");
        assert!(
            ell_r >= rows,
            "the randomness length must be at least n for Module-LWE",
        );
        assert!(psi >= 1, "the coefficient bound psi must be at least 1");
        CommitmentKey {
            b1: MatPolynomialRingZq::sample_uniform(rows, ell_m, modulus),
            b2: MatPolynomialRingZq::sample_uniform(rows, ell_r, modulus),
            psi,
        }
    }

    pub fn sample_randomness(&self) -> MatPolyOverZ { // sample `r` from `chi_r^{ell_r}`, coefficients bounded by `psi`
        let degree = self.b2.get_mod().get_degree();
        MatPolyOverZ::sample_uniform(
            self.b2.get_num_columns(),
            1,
            degree - 1,
            -self.psi,
            self.psi + 1,
        )
        .unwrap()
    }

    pub fn randomness_bound_sqrd(&self) -> Z { // return the bound `B_r = psi * sqrt(ell_r * d)` as its square
        let degree = self.b2.get_mod().get_degree();
        Z::from(self.psi * self.psi * self.b2.get_num_columns() * degree)
    }

    pub fn commit(&self, message: &MatPolyOverZ, randomness: &MatPolyOverZ) -> MatPolynomialRingZq { // compute `c = B_1 m + B_2 r`
        assert_eq!(
            (self.b1.get_num_columns(), 1),
            (message.get_num_rows(), message.get_num_columns()),
            "the message must be a column vector of length ell_m",
        );
        assert_eq!(
            (self.b2.get_num_columns(), 1),
            (randomness.get_num_rows(), randomness.get_num_columns()),
            "the randomness must be a column vector of length ell_r",
        );
        let modulus = self.b1.get_mod();
        let message_ring = MatPolynomialRingZq::from((message, &modulus));
        let randomness_ring = MatPolynomialRingZq::from((randomness, &modulus));
        &(&self.b1 * &message_ring) + &(&self.b2 * &randomness_ring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::norm_eucl_sqrd;
    use qfall_tools::utils::common_moduli::new_anticyclic;

    const D: i64 = 8;
    const Q: u64 = 257;
    const ROWS: i64 = 1;
    const ELL_M: i64 = 2;
    const ELL_R: i64 = 2;
    const PSI: i64 = 3;

    fn setup() -> (CommitmentKey, MatPolyOverZ, MatPolyOverZ) {
        let modulus = new_anticyclic(D, Q).unwrap();
        let key = CommitmentKey::generate(ELL_M, ELL_R, PSI, ROWS, &modulus);
        let message = MatPolyOverZ::sample_uniform(ELL_M, 1, D - 1, 0, 2).unwrap();
        let randomness = key.sample_randomness();
        (key, message, randomness)
    }

    #[test]
    fn commit_dimensions_and_determinism() {
        let (key, message, randomness) = setup();
        let commitment = key.commit(&message, &randomness);
        assert_eq!(ROWS, commitment.get_num_rows());
        assert_eq!(1, commitment.get_num_columns());
        assert_eq!(commitment, key.commit(&message, &randomness));
    }

    #[test]
    fn commit_is_linear_in_the_randomness() {
        let (key, message, randomness) = setup();
        let extra = key.sample_randomness();
        let modulus = key.b2.get_mod();
        let extra_ring = MatPolynomialRingZq::from((&extra, &modulus));
        let left = &key.commit(&message, &randomness) + &(&key.b2 * &extra_ring);
        let right = key.commit(&message, &(&randomness + &extra));
        assert_eq!(right, left);
    }

    #[test]
    fn fresh_randomness_changes_the_commitment() {
        let (key, message, randomness) = setup();
        let other = key.sample_randomness();
        assert_ne!(key.commit(&message, &randomness), key.commit(&message, &other));
    }

    // every sampled r must respect the bound B_r of the report
    #[test]
    fn randomness_respects_its_bound() {
        let (key, _, _) = setup();
        let bound = key.randomness_bound_sqrd();
        for _ in 0..20 {
            let randomness = key.sample_randomness();
            assert!(norm_eucl_sqrd(&randomness, D) <= bound);
        }
    }

    #[test]
    #[should_panic(expected = "at least n for Module-LWE")]
    fn short_randomness_length_is_rejected() {
        let modulus = new_anticyclic(D, Q).unwrap();
        CommitmentKey::generate(2, 1, PSI, 2, &modulus);
    }

    #[test]
    #[should_panic(expected = "column vector of length ell_m")]
    fn wrong_message_length_is_rejected() {
        let (key, _, randomness) = setup();
        let bad = MatPolyOverZ::new(ELL_M + 1, 1);
        key.commit(&bad, &randomness);
    }
}
