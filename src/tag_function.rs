//! The pluggable tag function `f : [N] -> R_q^n`, fixed per public
//! key. Report: "The Tag-Function Interface".

use qfall_math::integer::Z;
use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};

mod binary_encoding;

pub use binary_encoding::BinaryEncoding;

/// The fixed public tag function `f : [N] -> R_q^n`.
pub trait TagFunction {
    /// Returns the domain size `N`.
    fn domain_size(&self) -> Z;

    /// Returns the module rank `n`.
    fn rows(&self) -> i64;

    /// Returns the modulus of `R_q`.
    fn modulus(&self) -> &ModulusPolynomialRingZq;

    /// Evaluates `f(x)`; panics if `x` is outside `[N]`.
    fn eval(&self, x: &Z) -> MatPolynomialRingZq;
}

pub(crate) fn assert_tag_in_domain(x: &Z, n: &Z) {
    assert!(
        x >= &Z::ONE && x <= n,
        "tag x = {x} outside the domain [N] = [1, {n}]",
    );
}
