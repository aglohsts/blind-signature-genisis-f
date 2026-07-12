//! Shared helpers.

use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::traits::IntoCoefficientEmbedding;

/// Squared Euclidean norm of a polynomial vector, over its
/// coefficient embedding.
pub(crate) fn norm_eucl_sqrd(v: &MatPolyOverZ, degree: i64) -> Z {
    v.clone()
        .into_coefficient_embedding(degree)
        .norm_eucl_sqrd()
        .unwrap()
}
