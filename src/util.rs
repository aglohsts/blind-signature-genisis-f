//! Shared helpers.

use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::traits::IntoCoefficientEmbedding;

/// Squared Euclidean norm of a polynomial vector, taken over its
/// coefficients.
pub fn norm_eucl_sqrd(vector: &MatPolyOverZ, degree: i64) -> Z {
    vector
        .clone()
        .into_coefficient_embedding(degree)
        .norm_eucl_sqrd()
        .unwrap()
}
