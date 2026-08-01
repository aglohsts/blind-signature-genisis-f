// Shared helpers.

use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::traits::IntoCoefficientEmbedding;

pub fn norm_eucl_sqrd(vector: &MatPolyOverZ, degree: i64) -> Z { // squared Euclidean norm of a polynomial vector, over its coefficients
    vector
        .clone()
        .into_coefficient_embedding(degree)
        .norm_eucl_sqrd()
        .unwrap()
}

pub fn norm_inf(vector: &MatPolyOverZ, degree: i64) -> Z { // largest absolute coefficient of a polynomial vector
    vector
        .clone()
        .into_coefficient_embedding(degree)
        .norm_l_infty_infty()
}
