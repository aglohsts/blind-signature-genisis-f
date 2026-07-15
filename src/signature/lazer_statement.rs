use super::{BinarySignatureWitness, fits_ring_degree};
use crate::keys::PublicKey;
use crate::lazer_ffi::{self, Error};
use crate::tag_function::{BinaryEncoding, TagFunction};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::integer_mod_q::{MatPolynomialRingZq, MatZq};
use qfall_math::traits::{GetCoefficient, MatrixDimensions, MatrixGetEntry};
use qfall_tools::utils::common_moduli::new_anticyclic;

const MODULUS: u64 = 281_474_976_711_349;

pub(crate) struct LazerD64SignatureInputs {
    pub(crate) linear: Vec<i64>,
    pub(crate) tag_matrix: Vec<i64>,
    pub(crate) offset: Vec<i64>,
    pub(crate) witness: Vec<i64>,
    pub(crate) tag: Vec<i64>,
}

pub(crate) fn build_inputs(
    pk: &PublicKey<BinaryEncoding>,
    message: &MatPolyOverZ,
    witness: &BinarySignatureWitness,
) -> Result<LazerD64SignatureInputs, Error> {
    validate_profile(pk, message, witness)?;

    let mut linear = Vec::with_capacity(lazer_ffi::FINAL_LINEAR_COEFFICIENTS);
    append_ring_matrix(&mut linear, &pk.a, 1)?;
    append_ring_matrix(&mut linear, &pk.ck.b2, -1)?;

    let mut tag_matrix = Vec::with_capacity(lazer_ffi::FINAL_TAG_MATRIX_COEFFICIENTS);
    append_mod_q_matrix(&mut tag_matrix, pk.f.coefficient_matrix(), -1)?;

    let message_ring = MatPolynomialRingZq::from((message, pk.f.modulus()));
    let message_image = &pk.ck.b1 * &message_ring;
    let mut offset = Vec::with_capacity(lazer_ffi::FINAL_OFFSET_COEFFICIENTS);
    append_ring_matrix(&mut offset, &message_image, -1)?;

    let mut witness_coefficients = Vec::with_capacity(lazer_ffi::FINAL_WITNESS_COEFFICIENTS);
    append_integer_matrix(&mut witness_coefficients, &witness.s, 1)?;
    append_integer_matrix(&mut witness_coefficients, &witness.r, 1)?;

    let mut tag = Vec::with_capacity(lazer_ffi::FINAL_TAG_COEFFICIENTS);
    append_integer_entries(&mut tag, &witness.tag_encoding, 1)?;

    Ok(LazerD64SignatureInputs {
        linear,
        tag_matrix,
        offset,
        witness: witness_coefficients,
        tag,
    })
}

fn validate_profile(
    pk: &PublicKey<BinaryEncoding>,
    message: &MatPolyOverZ,
    witness: &BinarySignatureWitness,
) -> Result<(), Error> {
    let expected_modulus = new_anticyclic(lazer_ffi::DEGREE as i64, MODULUS).unwrap();
    if pk.f.modulus() != &expected_modulus {
        return Err(Error::ProfileMismatch(
            "the final-signature ring must be Z_q[X]/(X^64 + 1)",
        ));
    }
    if (pk.a.get_num_rows(), pk.a.get_num_columns())
        != (1, lazer_ffi::FINAL_PREIMAGE_COLUMNS as i64)
        || (pk.ck.b2.get_num_rows(), pk.ck.b2.get_num_columns())
            != (1, lazer_ffi::FINAL_RANDOMNESS_COLUMNS as i64)
        || pk.f.encoding_length() != lazer_ffi::FINAL_TAG_COEFFICIENTS as i64
    {
        return Err(Error::ProfileMismatch(
            "the final-signature dimensions must match the generated profile",
        ));
    }
    if (message.get_num_rows(), message.get_num_columns()) != (pk.ck.b1.get_num_columns(), 1)
        || (witness.s.get_num_rows(), witness.s.get_num_columns())
            != (lazer_ffi::FINAL_PREIMAGE_COLUMNS as i64, 1)
        || (witness.r.get_num_rows(), witness.r.get_num_columns())
            != (lazer_ffi::FINAL_RANDOMNESS_COLUMNS as i64, 1)
        || (
            witness.tag_encoding.get_num_rows(),
            witness.tag_encoding.get_num_columns(),
        ) != (lazer_ffi::FINAL_TAG_COEFFICIENTS as i64, 1)
        || !fits_ring_degree(message, lazer_ffi::DEGREE as i64)
        || !fits_ring_degree(&witness.s, lazer_ffi::DEGREE as i64)
        || !fits_ring_degree(&witness.r, lazer_ffi::DEGREE as i64)
    {
        return Err(Error::ProfileMismatch(
            "the final-signature values must match the profile layout",
        ));
    }
    Ok(())
}

fn append_ring_matrix(
    out: &mut Vec<i64>,
    matrix: &MatPolynomialRingZq,
    sign: i64,
) -> Result<(), Error> {
    append_integer_matrix(
        out,
        &matrix.get_representative_least_nonnegative_residue(),
        sign,
    )
}

fn append_mod_q_matrix(out: &mut Vec<i64>, matrix: &MatZq, sign: i64) -> Result<(), Error> {
    append_integer_entries(
        out,
        &matrix.get_representative_least_nonnegative_residue(),
        sign,
    )
}

fn append_integer_matrix(
    out: &mut Vec<i64>,
    matrix: &MatPolyOverZ,
    sign: i64,
) -> Result<(), Error> {
    for row in 0..matrix.get_num_rows() {
        for column in 0..matrix.get_num_columns() {
            let polynomial: PolyOverZ = matrix.get_entry(row, column).unwrap();
            for index in 0..lazer_ffi::DEGREE as i64 {
                let coefficient: Z = polynomial.get_coeff(index).unwrap();
                append_coefficient(out, &coefficient, sign)?;
            }
        }
    }
    Ok(())
}

fn append_integer_entries(
    out: &mut Vec<i64>,
    matrix: &qfall_math::integer::MatZ,
    sign: i64,
) -> Result<(), Error> {
    for row in 0..matrix.get_num_rows() {
        for column in 0..matrix.get_num_columns() {
            let coefficient: Z = matrix.get_entry(row, column).unwrap();
            append_coefficient(out, &coefficient, sign)?;
        }
    }
    Ok(())
}

fn append_coefficient(out: &mut Vec<i64>, coefficient: &Z, sign: i64) -> Result<(), Error> {
    let coefficient = i64::try_from(coefficient).map_err(|_| Error::CoefficientOutOfRange)?;
    out.push(coefficient * sign);
    Ok(())
}
