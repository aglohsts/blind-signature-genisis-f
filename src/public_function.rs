// report: "Instantiations of f"
// The public function interface `f: K x M x X -> R_q^n` of the
// GenISIS_f framework.

use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};

// A public function of the framework.
//
// The three associated types are the key space, the function-input
// space, and the function-randomness space. Each space supports
// efficient uniform sampling, as the framework requires. The key is
// sampled once by key generation; the input and the randomness are
// sampled by the signer in every issuing session.
pub trait PublicFunction {
    type Key;
    type Input;
    type Randomness;

    // The module rank `n`, so that `f` maps into `R_q^n`.
    fn rows(&self) -> i64;

    // The modulus of `R_q`.
    fn modulus(&self) -> &ModulusPolynomialRingZq;

    // Samples the function key `kappa` from `K`.
    fn sample_key(&self) -> Self::Key;

    // Samples the function input `mu` from `M`.
    fn sample_input(&self) -> Self::Input;

    // Samples the function randomness `xi` from `X`.
    fn sample_randomness(&self) -> Self::Randomness;

    // Whether `key` lies in `K`.
    fn contains_key(&self, key: &Self::Key) -> bool;

    // Whether `input` lies in `M`.
    fn contains_input(&self, input: &Self::Input) -> bool;

    // Whether `randomness` lies in `X`.
    fn contains_randomness(&self, randomness: &Self::Randomness) -> bool;

    // Evaluates `f(kappa, mu, xi)` as an `n x 1` matrix over `R_q`.
    fn eval(
        &self,
        key: &Self::Key,
        input: &Self::Input,
        randomness: &Self::Randomness,
    ) -> MatPolynomialRingZq;
}
