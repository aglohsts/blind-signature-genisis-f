//! The fixed-function public function
//! `f(mu) = Coeffs^{-1}(B * enc(mu))` of BLNS, Section 3.1.2.
//! Report: "Instantiations of f".

use qfall_math::integer::{MatPolyOverZ, MatZ, Z};
use qfall_math::integer_mod_q::{MatPolynomialRingZq, MatZq, ModulusPolynomialRingZq};
use qfall_math::traits::{FromCoefficientEmbedding, MatrixSetEntry, Pow};

/// The binary-encoding public function used by one public key.
///
/// The key space and the randomness space of the framework are
/// singletons here, so this function takes only the input `mu`. The
/// input space is `[2^t]`.
pub struct BinaryEncoding {
    b_mat: MatZq,
    modulus: ModulusPolynomialRingZq,
    rows: i64,
    t: i64,
}

impl BinaryEncoding {
    /// Samples `B` uniformly; supports `t` in `[1, 62]`.
    pub fn new(rows: i64, t: i64, modulus: ModulusPolynomialRingZq) -> BinaryEncoding {
        assert!(rows >= 1, "module rank n must be at least 1");
        assert!(
            (1..=62).contains(&t),
            "the prototype supports t in [1, 62] (2^t fits in i64)",
        );
        let degree = modulus.get_degree();
        let b_mat = MatZq::sample_uniform(rows * degree, t, modulus.get_q());
        BinaryEncoding {
            b_mat,
            modulus,
            rows,
            t,
        }
    }

    /// Returns the size `2^t` of the input space `M`.
    pub fn input_space(&self) -> Z {
        Z::from(2).pow(self.t).unwrap()
    }

    /// Samples the function input `mu` from `M`.
    pub fn sample_input(&self) -> Z {
        Z::sample_uniform(Z::ONE, self.input_space() + Z::ONE).unwrap()
    }

    /// Reports whether `input` lies in `M`.
    pub fn contains_input(&self, input: &Z) -> bool {
        input >= &Z::ONE && input <= &self.input_space()
    }

    /// Returns the module rank `n`.
    pub fn rows(&self) -> i64 {
        self.rows
    }

    /// Returns the modulus of `R_q`.
    pub fn modulus(&self) -> &ModulusPolynomialRingZq {
        &self.modulus
    }

    /// Evaluates `f(mu)` as an `n x 1` matrix over `R_q`.
    pub fn eval(&self, input: &Z) -> MatPolynomialRingZq {
        assert!(self.contains_input(input), "the input is outside M");
        let encoding = MatZq::from((&self.encode(input), self.modulus.get_q()));
        let product = &self.b_mat * &encoding;
        let coefficients = product.get_representative_least_nonnegative_residue();
        let polynomials = MatPolyOverZ::from_coefficient_embedding((
            &coefficients,
            self.modulus.get_degree() - 1,
        ));
        MatPolynomialRingZq::from((&polynomials, &self.modulus))
    }

    /// Returns the binary decomposition of `input - 1`.
    fn encode(&self, input: &Z) -> MatZ {
        let value = i64::try_from(&(input - Z::ONE)).unwrap();
        let mut encoding = MatZ::new(self.t, 1);
        for i in 0..self.t {
            encoding.set_entry(i, 0, (value >> i) & 1).unwrap();
        }
        encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfall_math::traits::MatrixDimensions;
    use qfall_tools::utils::common_moduli::new_anticyclic;

    const D: i64 = 8;
    const Q: u64 = 257;
    const ROWS: i64 = 2;
    const T: i64 = 10;

    fn setup() -> BinaryEncoding {
        BinaryEncoding::new(ROWS, T, new_anticyclic(D, Q).unwrap())
    }

    #[test]
    fn input_space_is_two_to_t() {
        assert_eq!(Z::from(1024), setup().input_space());
    }

    #[test]
    fn eval_dimensions_and_determinism() {
        let f = setup();
        let value = f.eval(&Z::from(5));
        assert_eq!(ROWS, value.get_num_rows());
        assert_eq!(1, value.get_num_columns());
        assert_eq!(value, f.eval(&Z::from(5)));
    }

    /// enc(1 - 1) is the zero vector, so f evaluates to zero.
    #[test]
    fn eval_of_one_is_zero() {
        let f = setup();
        let zero = MatPolynomialRingZq::from((&MatPolyOverZ::new(ROWS, 1), f.modulus()));
        assert_eq!(zero, f.eval(&Z::ONE));
    }

    #[test]
    fn distinct_inputs_distinct_outputs() {
        let f = setup();
        let values: Vec<_> = (1..=8).map(|i| f.eval(&Z::from(i))).collect();
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert_ne!(values[i], values[j]);
            }
        }
    }

    #[test]
    fn samples_stay_inside_the_input_space() {
        let f = setup();
        for _ in 0..20 {
            assert!(f.contains_input(&f.sample_input()));
        }
    }

    #[test]
    #[should_panic(expected = "outside M")]
    fn input_outside_the_space_is_rejected() {
        setup().eval(&Z::ZERO);
    }
}
