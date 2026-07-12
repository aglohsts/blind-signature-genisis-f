//! A hash-based tag function (random-oracle style).
//! Report: "Instantiations of f".

use super::{TagFunction, assert_tag_in_domain};
use qfall_math::integer::Z;
use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};
use qfall_schemes::hash::{HashInto, sha256::HashMatPolynomialRingZq};

/// `f(x) = H(sep || x)` over `R_q^n`, based on SHA-256 with a fixed
/// domain separator `sep`.
pub struct HashToRing {
    hasher: HashMatPolynomialRingZq,
    domain_size: Z,
    domain_separator: String,
}

impl HashToRing {
    /// Creates the function for the domain `[N]` with a fixed domain
    /// separator.
    pub fn new(
        rows: i64,
        domain_size: impl Into<Z>,
        modulus: ModulusPolynomialRingZq,
        domain_separator: impl Into<String>,
    ) -> Self {
        let domain_size = domain_size.into();
        assert!(rows >= 1, "module rank n must be at least 1");
        assert!(domain_size >= Z::ONE, "domain size N must be at least 1");
        Self {
            hasher: HashMatPolynomialRingZq {
                modulus,
                rows,
                cols: 1,
            },
            domain_size,
            domain_separator: domain_separator.into(),
        }
    }
}

impl TagFunction for HashToRing {
    fn domain_size(&self) -> Z {
        self.domain_size.clone()
    }

    fn rows(&self) -> i64 {
        self.hasher.rows
    }

    fn modulus(&self) -> &ModulusPolynomialRingZq {
        &self.hasher.modulus
    }

    fn eval(&self, x: &Z) -> MatPolynomialRingZq {
        assert_tag_in_domain(x, &self.domain_size);
        self.hasher
            .hash(&format!("{}|{}", self.domain_separator, x))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfall_math::traits::MatrixDimensions;
    use qfall_tools::utils::common_moduli::new_anticyclic;

    const D: i64 = 8;
    const Q: u64 = 257;
    const N_ROWS: i64 = 2;
    const N_TAGS: u64 = 1 << 20;

    fn setup() -> HashToRing {
        HashToRing::new(
            N_ROWS,
            N_TAGS,
            new_anticyclic(D, Q).unwrap(),
            "blind-sig-test",
        )
    }

    #[test]
    fn eval_dimensions_and_determinism() {
        let f = setup();
        let y = f.eval(&Z::from(42));
        assert_eq!(N_ROWS, y.get_num_rows());
        assert_eq!(1, y.get_num_columns());
        assert_eq!(y, f.eval(&Z::from(42)));
    }

    #[test]
    fn distinct_tags_distinct_outputs() {
        let f = setup();
        let images: Vec<_> = (1..=8).map(|x| f.eval(&Z::from(x))).collect();
        for i in 0..images.len() {
            for j in (i + 1)..images.len() {
                assert_ne!(images[i], images[j]);
            }
        }
    }

    #[test]
    fn domain_separation() {
        let modulus = new_anticyclic(D, Q).unwrap();
        let f = HashToRing::new(N_ROWS, N_TAGS, modulus.clone(), "sep-a");
        let g = HashToRing::new(N_ROWS, N_TAGS, modulus, "sep-b");
        assert_ne!(f.eval(&Z::from(7)), g.eval(&Z::from(7)));
    }

    #[test]
    #[should_panic(expected = "outside the domain")]
    fn tag_zero_rejected() {
        setup().eval(&Z::ZERO);
    }

    #[test]
    #[should_panic(expected = "outside the domain")]
    fn tag_above_n_rejected() {
        setup().eval(&Z::from(N_TAGS + 1));
    }
}
