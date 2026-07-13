//! The binary-encoding tag function of BLNS, Section 3.1.2.
//! Report: "Instantiations of f".

use super::{assert_tag_in_domain, TagFunction};
use qfall_math::integer::{MatPolyOverZ, MatZ, Z};
use qfall_math::integer_mod_q::{MatPolynomialRingZq, MatZq, ModulusPolynomialRingZq};
use qfall_math::traits::{FromCoefficientEmbedding, MatrixSetEntry, Pow};

/// `f(x) = Coeffs^{-1}(B * enc(x))` with uniform `B in Z_q^{nd x t}`,
/// where `enc(x)` is the binary decomposition of `x - 1` and `N = 2^t`.
pub struct BinaryEncoding {
    b_mat: MatZq,
    modulus: ModulusPolynomialRingZq,
    rows: i64,
    t: i64,
}

impl BinaryEncoding {
    /// Samples `B` uniformly for a positive encoding length `t`.
    pub fn new(rows: i64, t: i64, modulus: ModulusPolynomialRingZq) -> Self {
        assert!(rows >= 1, "module rank n must be at least 1");
        assert!(t >= 1, "encoding length t must be at least 1");
        let d = modulus.get_degree();
        let b_mat = MatZq::sample_uniform(rows * d, t, modulus.get_q());
        Self {
            b_mat,
            modulus,
            rows,
            t,
        }
    }

    fn encode(&self, x: &Z) -> MatZ {
        let bits = (x - Z::ONE).to_bits();
        let mut enc = MatZ::new(self.t, 1);
        for i in 0..self.t {
            enc.set_entry(
                i,
                0,
                u8::from(bits.get(i as usize).copied().unwrap_or(false)),
            )
            .unwrap();
        }
        enc
    }
}

impl TagFunction for BinaryEncoding {
    fn domain_size(&self) -> Z {
        Z::from(2).pow(self.t).unwrap()
    }

    fn rows(&self) -> i64 {
        self.rows
    }

    fn modulus(&self) -> &ModulusPolynomialRingZq {
        &self.modulus
    }

    fn eval(&self, x: &Z) -> MatPolynomialRingZq {
        assert_tag_in_domain(x, &self.domain_size());
        let enc = MatZq::from((&self.encode(x), self.modulus.get_q()));
        let embedding = (&self.b_mat * &enc).get_representative_least_nonnegative_residue();
        let poly_mat =
            MatPolyOverZ::from_coefficient_embedding((&embedding, self.modulus.get_degree() - 1));
        MatPolynomialRingZq::from((&poly_mat, &self.modulus))
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
    const T: i64 = 10;
    const PAPER_ALT_D: i64 = 1024;
    const PAPER_ALT_Q: u64 = 33_641;
    const PAPER_ALT_T: i64 = 256;

    fn setup() -> BinaryEncoding {
        BinaryEncoding::new(N_ROWS, T, new_anticyclic(D, Q).unwrap())
    }

    #[test]
    fn domain_size_is_two_to_t() {
        let f = setup();
        assert_eq!(Z::from(1024), f.domain_size());
    }

    #[test]
    fn eval_dimensions_and_determinism() {
        let f = setup();
        let y = f.eval(&Z::from(5));
        assert_eq!(N_ROWS, y.get_num_rows());
        assert_eq!(1, y.get_num_columns());
        assert_eq!(y, f.eval(&Z::from(5)));
    }

    #[test]
    fn eval_of_one_is_zero() {
        let f = setup();
        let zero = MatPolynomialRingZq::from((&MatPolyOverZ::new(N_ROWS, 1), f.modulus()));
        assert_eq!(zero, f.eval(&Z::ONE));
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
    #[should_panic(expected = "outside the domain")]
    fn tag_zero_rejected() {
        setup().eval(&Z::ZERO);
    }

    #[test]
    #[should_panic(expected = "outside the domain")]
    fn tag_above_n_rejected() {
        setup().eval(&Z::from(1025));
    }

    #[test]
    fn paper_alternative_profile_supports_full_tag_domain() {
        let f = BinaryEncoding::new(
            1,
            PAPER_ALT_T,
            new_anticyclic(PAPER_ALT_D, PAPER_ALT_Q).unwrap(),
        );
        let largest_tag = Z::from(2).pow(PAPER_ALT_T).unwrap();
        let image = f.eval(&largest_tag);
        assert_eq!(largest_tag, f.domain_size());
        assert_eq!(1, image.get_num_rows());
        assert_eq!(1, image.get_num_columns());
    }
}
