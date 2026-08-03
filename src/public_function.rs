// report: "Instantiations of f"
// public function interface `f: K x M x X -> R_q^n` of GenISIS_f

use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};

// the key is sampled once by key generation
// the input and the randomness are sampled by the signer in every issuing session
pub trait PublicFunction {
    type Key;
    type Input;
    type Randomness;

    // module rank `n`, so that `f` maps into `R_q^n`
    fn rows(&self) -> i64;

    // modulus of `R_q`
    fn modulus(&self) -> &ModulusPolynomialRingZq;

    // sample the function key `kappa` from `K`
    fn sample_key(&self) -> Self::Key;

    // sample the function input `mu` from `M`
    fn sample_input(&self) -> Self::Input;

    // sample the function randomness `xi` from `X`
    fn sample_randomness(&self) -> Self::Randomness;

    // whether `key` lies in `K`
    fn contains_key(&self, key: &Self::Key) -> bool;

    // whether `input` lies in `M`
    fn contains_input(&self, input: &Self::Input) -> bool;

    // whether `randomness` lies in `X`
    fn contains_randomness(&self, randomness: &Self::Randomness) -> bool;

    // evaluate `f(kappa, mu, xi)` as an `n x 1` matrix over `R_q`
    fn eval(
        &self,
        key: &Self::Key,
        input: &Self::Input,
        randomness: &Self::Randomness,
    ) -> MatPolynomialRingZq;
}
