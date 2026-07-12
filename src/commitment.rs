//! The commitment `c = B_1 * m + B_2 * r` over `R_q`.
//! Report: "The Commitment and the Protocol Layer".

use qfall_math::integer::MatPolyOverZ;
use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};
use qfall_math::rational::Q;
use qfall_math::traits::MatrixDimensions;

/// The public commitment matrices `B_1` and `B_2`.
pub struct CommitmentKey {
    pub b1: MatPolynomialRingZq,
    pub b2: MatPolynomialRingZq,
}

impl CommitmentKey {
    /// Samples uniform `B_1 in R_q^{1 x l_m}` and `B_2 in R_q^{1 x l_r}`.
    pub fn generate(ell_m: i64, ell_r: i64, modulus: &ModulusPolynomialRingZq) -> Self {
        assert!(ell_m >= 1, "the message length l_m must be at least 1");
        assert!(
            ell_r >= 1,
            "the randomness length l_r must be at least n = 1 for MLWE hiding",
        );
        Self {
            b1: MatPolynomialRingZq::sample_uniform(1, ell_m, modulus),
            b2: MatPolynomialRingZq::sample_uniform(1, ell_r, modulus),
        }
    }

    /// Samples `r <- chi_r^{l_r}`, independently of the message.
    pub fn sample_randomness(&self, s_r: &Q) -> MatPolyOverZ {
        let degree = self.b2.get_mod().get_degree() - 1;
        MatPolyOverZ::sample_discrete_gauss(self.b2.get_num_columns(), 1, degree, 0, s_r).unwrap()
    }

    /// Computes `c = B_1 * m + B_2 * r`; panics on wrong dimensions.
    pub fn commit(&self, m: &MatPolyOverZ, r: &MatPolyOverZ) -> MatPolynomialRingZq {
        assert_eq!(
            (self.b1.get_num_columns(), 1),
            (m.get_num_rows(), m.get_num_columns()),
            "the message must be a column vector of length l_m",
        );
        assert_eq!(
            (self.b2.get_num_columns(), 1),
            (r.get_num_rows(), r.get_num_columns()),
            "the randomness must be a column vector of length l_r",
        );
        let modulus = self.b1.get_mod();
        let m_ring = MatPolynomialRingZq::from((m, &modulus));
        let r_ring = MatPolynomialRingZq::from((r, &modulus));
        &(&self.b1 * &m_ring) + &(&self.b2 * &r_ring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfall_tools::utils::common_moduli::new_anticyclic;

    const D: i64 = 8;
    const Q_MOD: u64 = 257;
    const ELL_M: i64 = 2;
    const ELL_R: i64 = 2;

    fn setup() -> (CommitmentKey, MatPolyOverZ, MatPolyOverZ) {
        let modulus = new_anticyclic(D, Q_MOD).unwrap();
        let ck = CommitmentKey::generate(ELL_M, ELL_R, &modulus);
        let m = MatPolyOverZ::sample_uniform(ELL_M, 1, D - 1, 0, 2).unwrap();
        let r = ck.sample_randomness(&Q::from(3));
        (ck, m, r)
    }

    #[test]
    fn commit_dimensions_and_determinism() {
        let (ck, m, r) = setup();
        let c = ck.commit(&m, &r);
        assert_eq!(1, c.get_num_rows());
        assert_eq!(1, c.get_num_columns());
        assert_eq!(c, ck.commit(&m, &r));
    }

    #[test]
    fn commit_is_linear_in_the_randomness() {
        let (ck, m, r) = setup();
        let r_prime = ck.sample_randomness(&Q::from(3));
        let modulus = ck.b2.get_mod();
        let r_prime_ring = MatPolynomialRingZq::from((&r_prime, &modulus));
        let lhs = &ck.commit(&m, &r) + &(&ck.b2 * &r_prime_ring);
        let rhs = ck.commit(&m, &(&r + &r_prime));
        assert_eq!(rhs, lhs);
    }

    #[test]
    fn fresh_randomness_changes_the_commitment() {
        let (ck, m, r) = setup();
        let r_prime = ck.sample_randomness(&Q::from(3));
        assert_ne!(ck.commit(&m, &r), ck.commit(&m, &r_prime));
    }

    #[test]
    #[should_panic(expected = "column vector of length l_m")]
    fn wrong_message_dimension_rejected() {
        let (ck, _, r) = setup();
        let bad_m = MatPolyOverZ::new(ELL_M + 1, 1);
        ck.commit(&bad_m, &r);
    }
}
