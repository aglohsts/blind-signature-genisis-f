// report: "Instantiations of f"
use crate::public_function::PublicFunction;
use qfall_math::integer::Z;
use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};
use qfall_schemes::hash::{HashInto, sha256::HashMatPolynomialRingZq};

// `f(kappa, mu, xi) = H(sep || kappa || mu || xi)` over `R_q^n`.
pub struct HashToRing {
    hasher: HashMatPolynomialRingZq,
    key_space: Z,
    input_space: Z,
    randomness_space: Z,
    domain_separator: String,
}

impl HashToRing {
    pub fn new(
        rows: i64,
        key_space: impl Into<Z>,
        input_space: impl Into<Z>,
        randomness_space: impl Into<Z>,
        modulus: ModulusPolynomialRingZq,
        domain_separator: impl Into<String>,
    ) -> HashToRing { // creates the function for the given space sizes
        let key_space = key_space.into();
        let input_space = input_space.into();
        let randomness_space = randomness_space.into();
        assert!(rows >= 1, "module rank n must be at least 1");
        assert!(key_space >= Z::ONE, "key space must not be empty");
        assert!(input_space >= Z::ONE, "input space must not be empty");
        assert!(
            randomness_space >= Z::ONE,
            "randomness space must not be empty",
        );
        HashToRing {
            hasher: HashMatPolynomialRingZq {
                modulus,
                rows,
                cols: 1,
            },
            key_space,
            input_space,
            randomness_space,
            domain_separator: domain_separator.into(),
        }
    }
}

impl PublicFunction for HashToRing {
    type Key = Z;
    type Input = Z;
    type Randomness = Z;

    fn rows(&self) -> i64 { // returns the module rank `n`
        self.hasher.rows
    }

    fn modulus(&self) -> &ModulusPolynomialRingZq { // returns the modulus of `R_q`
        &self.hasher.modulus
    }

    fn sample_key(&self) -> Z { // samples the function key `kappa` from `K`
        sample_in(&self.key_space)
    }

    fn sample_input(&self) -> Z { // samples the function input `mu` from `M`
        sample_in(&self.input_space)
    }

    fn sample_randomness(&self) -> Z { // samples the function randomness `xi` from `X`
        sample_in(&self.randomness_space)
    }

    fn contains_key(&self, key: &Z) -> bool { // whether `key` lies in `K`
        is_in(key, &self.key_space)
    }

    fn contains_input(&self, input: &Z) -> bool { // whether `input` lies in `M`
        is_in(input, &self.input_space)
    }

    fn contains_randomness(&self, randomness: &Z) -> bool { // whether `randomness` lies in `X`
        is_in(randomness, &self.randomness_space)
    }

    fn eval(&self, key: &Z, input: &Z, randomness: &Z) -> MatPolynomialRingZq { // evaluates `f(kappa, mu, xi)` as an `n x 1` matrix over `R_q`
        assert!(self.contains_key(key), "the key is outside K");
        assert!(self.contains_input(input), "the input is outside M");
        assert!(
            self.contains_randomness(randomness),
            "the randomness is outside X",
        );
        self.hasher.hash(&format!(
            "{}|{}|{}|{}",
            self.domain_separator, key, input, randomness
        ))
    }
}

fn sample_in(size: &Z) -> Z {
    Z::sample_uniform(Z::ONE, size + Z::ONE).unwrap()
}

fn is_in(value: &Z, size: &Z) -> bool {
    value >= &Z::ONE && value <= size
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfall_math::traits::MatrixDimensions;
    use qfall_tools::utils::common_moduli::new_anticyclic;

    const D: i64 = 8;
    const Q: u64 = 257;
    const ROWS: i64 = 2;

    fn setup() -> HashToRing {
        HashToRing::new(
            ROWS,
            1u64 << 10,
            1u64 << 20,
            1u64 << 10,
            new_anticyclic(D, Q).unwrap(),
            "gen-tag-test",
        )
    }

    #[test]
    fn eval_dimensions_and_determinism() {
        let f = setup();
        let key = Z::from(3);
        let input = Z::from(42);
        let randomness = Z::from(7);
        let value = f.eval(&key, &input, &randomness);
        assert_eq!(ROWS, value.get_num_rows());
        assert_eq!(1, value.get_num_columns());
        assert_eq!(value, f.eval(&key, &input, &randomness));
    }

    #[test]
    fn every_argument_changes_the_output() {
        let f = setup();
        let base = f.eval(&Z::from(3), &Z::from(42), &Z::from(7));
        assert_ne!(base, f.eval(&Z::from(4), &Z::from(42), &Z::from(7)));
        assert_ne!(base, f.eval(&Z::from(3), &Z::from(43), &Z::from(7)));
        assert_ne!(base, f.eval(&Z::from(3), &Z::from(42), &Z::from(8)));
    }

    #[test]
    fn samples_stay_inside_their_spaces() {
        let f = setup();
        for _ in 0..20 {
            assert!(f.contains_input(&f.sample_input()));
            assert!(f.contains_randomness(&f.sample_randomness()));
        }
    }

    #[test]
    fn domain_separation() {
        let modulus = new_anticyclic(D, Q).unwrap();
        let f = HashToRing::new(ROWS, 8u64, 8u64, 8u64, modulus.clone(), "sep-a");
        let g = HashToRing::new(ROWS, 8u64, 8u64, 8u64, modulus, "sep-b");
        let key = Z::ONE;
        let input = Z::from(2);
        let randomness = Z::from(3);
        assert_ne!(
            f.eval(&key, &input, &randomness),
            g.eval(&key, &input, &randomness)
        );
    }

    #[test]
    #[should_panic(expected = "outside M")]
    fn input_outside_the_space_is_rejected() {
        setup().eval(&Z::ONE, &Z::ZERO, &Z::ONE);
    }
}
