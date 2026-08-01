// report: "Instantiations of f"
// An algebraic public function
// `f(kappa, mu, xi) = kappa * xi + G * enc(mu)` over `R_q^n`.
//
// This is the keyed and probabilistic instantiation used by the LaZer
// proofs. Both terms are linear in their argument, so the whole
// signing relation stays linear over `R_q`: the encoding `enc(mu)` is
// a binary vector, and the function randomness `xi` is short. These
// are exactly the two witness shapes that a lattice proof system can
// handle, which the hash-based instantiation cannot provide.
//
// The key space is `K = R_q^{n x ell_xi}`, the input space is
// `M = [2^t]`, and the randomness space is `X = S_psi^{ell_xi}`. All
// three support efficient uniform sampling.

use crate::public_function::PublicFunction;
use crate::util::norm_inf;
use qfall_math::integer::{MatPolyOverZ, MatZ, Z};
use qfall_math::integer_mod_q::{MatPolynomialRingZq, MatZq, ModulusPolynomialRingZq};
use qfall_math::traits::{
    FromCoefficientEmbedding, MatrixDimensions, MatrixSetEntry, Pow,
};

// The algebraic public function used by one public key.
pub struct ModuleLweEncoding {
    // The encoding matrix `G`, held in its coefficient embedding.
    g_mat: MatZq,
    modulus: ModulusPolynomialRingZq,
    rows: i64,
    t: i64,
    ell_xi: i64,
    psi_xi: i64,
}

impl ModuleLweEncoding {
    // Samples the encoding matrix `G`. The input space is `[2^t]`, so
    // `t` is bounded as in the binary encoding. The function
    // randomness has `ell_xi` entries with coefficients bounded by
    // `psi_xi`.
    pub fn new(
        rows: i64,
        t: i64,
        ell_xi: i64,
        psi_xi: i64,
        modulus: ModulusPolynomialRingZq,
    ) -> ModuleLweEncoding {
        assert!(rows >= 1, "module rank n must be at least 1");
        assert!(t >= 1, "the encoding length t must be at least 1");
        assert!(ell_xi >= 1, "the randomness length must be at least 1");
        assert!(psi_xi >= 1, "the coefficient bound psi_xi must be at least 1");
        let degree = modulus.get_degree();
        let g_mat = MatZq::sample_uniform(rows * degree, t, modulus.get_q());
        ModuleLweEncoding {
            g_mat,
            modulus,
            rows,
            t,
            ell_xi,
            psi_xi,
        }
    }

    pub fn input_space(&self) -> Z { // returns the size `2^t` of the input space `M`
        Z::from(2).pow(self.t).unwrap()
    }

    pub fn bits(&self) -> i64 { // returns the number of encoded bits `t`
        self.t
    }

    pub fn randomness_length(&self) -> i64 { // returns the length `ell_xi` of the function randomness
        self.ell_xi
    }

    pub fn randomness_bound_sqrd(&self) -> Z { // returns the bound `B_xi = psi_xi * sqrt(ell_xi * d)` as its square
        let degree = self.modulus.get_degree();
        Z::from(self.psi_xi * self.psi_xi * self.ell_xi * degree)
    }

    // The LaZer statement builder reads it column by column.
    pub fn encoding_matrix(&self) -> &MatZq { // returns the encoding matrix `G` in its coefficient embedding
        &self.g_mat
    }

    // This is the binary part of the witness of the final-signature
    // relation.
    pub fn encode(&self, input: &Z) -> MatZ { // returns the binary decomposition of `input - 1` as a `t x 1` integer matrix
        assert!(self.contains_input(input), "the input is outside M");
        let bits = (input - Z::ONE).to_bits();
        let mut encoding = MatZ::new(self.t, 1);
        for i in 0..self.t {
            let bit = bits.get(i as usize).copied().unwrap_or(false);
            encoding.set_entry(i, 0, u8::from(bit)).unwrap();
        }
        encoding
    }

    // The LaZer statement uses this term separately from the masking
    // term.
    pub fn eval_encoding(&self, encoding: &MatZ) -> Option<MatPolynomialRingZq> { // evaluates the encoding term `G * enc(mu)` on its own
        if encoding.get_num_rows() != self.t || encoding.get_num_columns() != 1 {
            return None;
        }
        let embedded = MatZq::from((encoding, self.modulus.get_q()));
        let product = &self.g_mat * &embedded;
        let coefficients = product.get_representative_least_nonnegative_residue();
        let polynomials =
            MatPolyOverZ::from_coefficient_embedding((&coefficients, self.modulus.get_degree() - 1));
        Some(MatPolynomialRingZq::from((&polynomials, &self.modulus)))
    }
}

impl PublicFunction for ModuleLweEncoding {
    type Key = MatPolynomialRingZq;
    type Input = Z;
    type Randomness = MatPolyOverZ;

    fn rows(&self) -> i64 {
        self.rows
    }

    fn modulus(&self) -> &ModulusPolynomialRingZq {
        &self.modulus
    }

    fn sample_key(&self) -> MatPolynomialRingZq {
        MatPolynomialRingZq::sample_uniform(self.rows, self.ell_xi, &self.modulus)
    }

    fn sample_input(&self) -> Z {
        Z::sample_uniform(Z::ONE, self.input_space() + Z::ONE).unwrap()
    }

    fn sample_randomness(&self) -> MatPolyOverZ {
        let degree = self.modulus.get_degree();
        MatPolyOverZ::sample_uniform(self.ell_xi, 1, degree - 1, -self.psi_xi, self.psi_xi + 1)
            .unwrap()
    }

    fn contains_key(&self, key: &MatPolynomialRingZq) -> bool {
        key.get_num_rows() == self.rows
            && key.get_num_columns() == self.ell_xi
            && &key.get_mod() == &self.modulus
    }

    fn contains_input(&self, input: &Z) -> bool {
        input >= &Z::ONE && input <= &self.input_space()
    }

    fn contains_randomness(&self, randomness: &MatPolyOverZ) -> bool {
        randomness.get_num_rows() == self.ell_xi
            && randomness.get_num_columns() == 1
            && norm_inf(randomness, self.modulus.get_degree()) <= Z::from(self.psi_xi)
    }

    fn eval(
        &self,
        key: &MatPolynomialRingZq,
        input: &Z,
        randomness: &MatPolyOverZ,
    ) -> MatPolynomialRingZq { // `f(kappa, mu, xi) = kappa * xi + G * enc(mu)`
        assert!(self.contains_key(key), "the key is outside K");
        assert!(self.contains_input(input), "the input is outside M");
        assert!(
            self.contains_randomness(randomness),
            "the randomness is outside X",
        );
        let randomness_ring = MatPolynomialRingZq::from((randomness, &self.modulus));
        let masking = key * &randomness_ring;
        &masking + &self.eval_encoding(&self.encode(input)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfall_math::traits::MatrixGetEntry;
    use qfall_tools::utils::common_moduli::new_anticyclic;

    const D: i64 = 8;
    const Q: u64 = 257;
    const ROWS: i64 = 1;
    const T: i64 = 10;
    const ELL_XI: i64 = 2;
    const PSI_XI: i64 = 3;

    fn setup() -> ModuleLweEncoding {
        ModuleLweEncoding::new(ROWS, T, ELL_XI, PSI_XI, new_anticyclic(D, Q).unwrap())
    }

    #[test]
    fn input_space_is_two_to_t() {
        assert_eq!(Z::from(1024), setup().input_space());
    }

    #[test]
    fn eval_dimensions_and_determinism() {
        let f = setup();
        let key = f.sample_key();
        let randomness = f.sample_randomness();
        let value = f.eval(&key, &Z::from(5), &randomness);
        assert_eq!(ROWS, value.get_num_rows());
        assert_eq!(1, value.get_num_columns());
        assert_eq!(value, f.eval(&key, &Z::from(5), &randomness));
    }

    #[test]
    fn every_argument_changes_the_output() {
        let f = setup();
        let key = f.sample_key();
        let randomness = f.sample_randomness();
        let base = f.eval(&key, &Z::from(5), &randomness);

        let mut other_key = f.sample_key();
        while other_key == key {
            other_key = f.sample_key();
        }
        assert_ne!(base, f.eval(&other_key, &Z::from(5), &randomness));
        assert_ne!(base, f.eval(&key, &Z::from(6), &randomness));

        let mut other_randomness = f.sample_randomness();
        while other_randomness == randomness {
            other_randomness = f.sample_randomness();
        }
        assert_ne!(base, f.eval(&key, &Z::from(5), &other_randomness));
    }

    // linearity is the property the LaZer statement relies on
    #[test]
    fn eval_is_linear_in_the_randomness() {
        let f = setup();
        let key = f.sample_key();
        let first = f.sample_randomness();
        let second = f.sample_randomness();
        let modulus = f.modulus();
        let sum_ring = MatPolynomialRingZq::from((&(&first + &second), modulus));
        let encoding = f.eval_encoding(&f.encode(&Z::from(5))).unwrap();

        let combined = &(&key * &sum_ring) + &encoding;
        let separate = &f.eval(&key, &Z::from(5), &first)
            + &(&key * &MatPolynomialRingZq::from((&second, modulus)));
        assert_eq!(combined, separate);
    }

    // enc(1 - 1) is the zero vector, so only the masking term remains
    #[test]
    fn input_one_leaves_only_the_masking_term() {
        let f = setup();
        let key = f.sample_key();
        let randomness = f.sample_randomness();
        let randomness_ring = MatPolynomialRingZq::from((&randomness, f.modulus()));
        assert_eq!(&key * &randomness_ring, f.eval(&key, &Z::ONE, &randomness));
    }

    #[test]
    fn encoding_is_binary_and_has_full_length() {
        let f = setup();
        let encoding = f.encode(&Z::from(683));
        assert_eq!(T, encoding.get_num_rows());
        for i in 0..T {
            let bit: Z = encoding.get_entry(i, 0).unwrap();
            assert!(bit == Z::ZERO || bit == Z::ONE);
        }
    }

    #[test]
    fn distinct_inputs_distinct_encodings() {
        let f = setup();
        let values: Vec<_> = (1..=8).map(|i| f.encode(&Z::from(i))).collect();
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert_ne!(values[i], values[j]);
            }
        }
    }

    #[test]
    fn samples_stay_inside_their_spaces() {
        let f = setup();
        for _ in 0..20 {
            assert!(f.contains_key(&f.sample_key()));
            assert!(f.contains_input(&f.sample_input()));
            assert!(f.contains_randomness(&f.sample_randomness()));
        }
    }

    // every sampled xi respects the bound used by the proof relation
    #[test]
    fn randomness_respects_its_bound() {
        let f = setup();
        let bound = f.randomness_bound_sqrd();
        for _ in 0..20 {
            assert!(crate::util::norm_eucl_sqrd(&f.sample_randomness(), D) <= bound);
        }
    }

    #[test]
    #[should_panic(expected = "outside M")]
    fn input_outside_the_space_is_rejected() {
        let f = setup();
        let key = f.sample_key();
        let randomness = f.sample_randomness();
        f.eval(&key, &Z::ZERO, &randomness);
    }

    #[test]
    #[should_panic(expected = "outside X")]
    fn oversized_randomness_is_rejected() {
        let f = setup();
        let key = f.sample_key();
        let big = MatPolyOverZ::sample_uniform(ELL_XI, 1, D - 1, 100, 200).unwrap();
        f.eval(&key, &Z::from(5), &big);
    }
}
