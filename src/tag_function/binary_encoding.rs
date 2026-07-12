//! The binary-encoding tag function of BLNS, Section 3.1.2.
//! Report: "Instantiations of f".

use super::{TagFunction, assert_tag_in_domain};
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
    /// Samples `B` uniformly; supports `t` in `[1, 62]`.
    pub fn new(rows: i64, t: i64, modulus: ModulusPolynomialRingZq) -> Self {
        assert!(rows >= 1, "module rank n must be at least 1");
        assert!(
            (1..=62).contains(&t),
            "the prototype supports t in [1, 62] (N = 2^t fits in i64)",
        );
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
        let value = i64::try_from(&(x - Z::ONE)).unwrap();
        let mut enc = MatZ::new(self.t, 1);
        for i in 0..self.t {
            enc.set_entry(i, 0, (value >> i) & 1).unwrap();
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
}
