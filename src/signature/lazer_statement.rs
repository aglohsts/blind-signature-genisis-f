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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::CommitmentKey;
    use crate::keys::PublicKey;
    use crate::proof_com::ComProofParams;
    use crate::signature::binary_relation_holds;
    use qfall_math::integer::PolyOverZ;
    use qfall_math::rational::Q;
    use qfall_math::traits::{MatrixSetEntry, SetCoefficient};
    use qfall_tools::primitive::psf::PSFGPVRing;
    use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;

    fn profile_fixture() -> (
        PublicKey<BinaryEncoding>,
        MatPolyOverZ,
        BinarySignatureWitness,
    ) {
        let modulus = new_anticyclic(lazer_ffi::DEGREE as i64, MODULUS).unwrap();
        let mut a = MatPolyOverZ::new(1, lazer_ffi::FINAL_PREIMAGE_COLUMNS as i64);
        let mut x = PolyOverZ::default();
        x.set_coeff(1, 1).unwrap();
        a.set_entry(0, 0, x).unwrap();

        let mut b1 = MatPolyOverZ::new(1, 2);
        b1.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
        let mut b2 = MatPolyOverZ::new(1, 2);
        b2.set_entry(0, 0, PolyOverZ::from(1)).unwrap();

        let f = BinaryEncoding::new(1, lazer_ffi::FINAL_TAG_COEFFICIENTS as i64, modulus.clone());
        let psf = PSFGPVRing {
            gp: GadgetParametersRing::init_default(lazer_ffi::DEGREE as i64, MODULUS),
            s: Q::from(100),
            s_td: Q::from(1.005_f64),
        };
        let pk = PublicKey {
            a: MatPolynomialRingZq::from((&a, &modulus)),
            ck: CommitmentKey {
                b1: MatPolynomialRingZq::from((&b1, &modulus)),
                b2: MatPolynomialRingZq::from((&b2, &modulus)),
            },
            f,
            psf,
            s_r: Q::from(3),
            beta_msg_sqrd: Z::from(16),
            beta_r_sqrd: Z::from(2_000),
            com_params: ComProofParams {
                witness_inf: 20,
                mask_inf: 8_000,
            },
        };

        let mut message = MatPolyOverZ::new(2, 1);
        message.set_entry(0, 0, PolyOverZ::from(-3)).unwrap();
        let mut s = MatPolyOverZ::new(lazer_ffi::FINAL_PREIMAGE_COLUMNS as i64, 1);
        let mut last = PolyOverZ::default();
        last.set_coeff(lazer_ffi::DEGREE as i64 - 1, 2).unwrap();
        s.set_entry(0, 0, last).unwrap();
        let mut r = MatPolyOverZ::new(lazer_ffi::FINAL_RANDOMNESS_COLUMNS as i64, 1);
        r.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
        let tag_encoding = pk.f.encode_tag(&Z::ONE);
        let witness = BinarySignatureWitness { tag_encoding, s, r };
        (pk, message, witness)
    }

    fn coefficient_relation_holds(inputs: &LazerD64SignatureInputs) -> bool {
        let degree = lazer_ffi::DEGREE;
        let modulus = MODULUS as i128;
        (0..degree).all(|row| {
            let mut residual = inputs.offset[row] as i128;
            for column in 0..lazer_ffi::FINAL_BOUNDED_COLUMNS {
                let polynomial = &inputs.linear[column * degree..(column + 1) * degree];
                let value = &inputs.witness[column * degree..(column + 1) * degree];
                for (left, left_value) in polynomial.iter().enumerate() {
                    for (right, right_value) in value.iter().enumerate() {
                        let exponent = left + right;
                        if exponent % degree == row {
                            let sign = if exponent >= degree { -1 } else { 1 };
                            residual += sign * (*left_value as i128) * (*right_value as i128);
                        }
                    }
                }
            }
            for bit in 0..lazer_ffi::FINAL_TAG_COEFFICIENTS {
                residual += inputs.tag_matrix[row * degree + bit] as i128 * inputs.tag[bit] as i128;
            }
            residual.rem_euclid(modulus) == 0
        })
    }

    #[test]
    fn scheme_relation_matches_coefficient_statement() {
        let (pk, message, witness) = profile_fixture();
        assert!(binary_relation_holds(&pk, &message, &witness));
        let inputs = build_inputs(&pk, &message, &witness).expect("build statement inputs");
        assert!(coefficient_relation_holds(&inputs));
        assert_eq!(lazer_ffi::FINAL_LINEAR_COEFFICIENTS, inputs.linear.len());
        assert_eq!(
            lazer_ffi::FINAL_TAG_MATRIX_COEFFICIENTS,
            inputs.tag_matrix.len()
        );
        assert_eq!(lazer_ffi::FINAL_OFFSET_COEFFICIENTS, inputs.offset.len());
        assert_eq!(lazer_ffi::FINAL_WITNESS_COEFFICIENTS, inputs.witness.len());
        assert_eq!(lazer_ffi::FINAL_TAG_COEFFICIENTS, inputs.tag.len());

        let ppseed = [7; 32];
        let proof = lazer_ffi::prove_final_signature(
            &inputs.linear,
            &inputs.tag_matrix,
            &inputs.offset,
            &inputs.witness,
            &inputs.tag,
            &ppseed,
            Some(&[9; 32]),
        )
        .expect("prove mapped relation");
        assert!(
            lazer_ffi::verify_final_signature(
                &inputs.linear,
                &inputs.tag_matrix,
                &inputs.offset,
                &ppseed,
                &proof,
            )
            .expect("verify mapped relation")
        );
    }

    #[test]
    fn coefficient_statement_rejects_altered_scheme_values() {
        let (pk, message, witness) = profile_fixture();

        let mut altered_message = message.clone();
        altered_message
            .set_entry(0, 0, PolyOverZ::from(-2))
            .unwrap();
        let inputs = build_inputs(&pk, &altered_message, &witness).expect("altered message");
        assert!(!binary_relation_holds(&pk, &altered_message, &witness));
        assert!(!coefficient_relation_holds(&inputs));

        let mut altered_s = BinarySignatureWitness {
            tag_encoding: witness.tag_encoding.clone(),
            s: witness.s.clone(),
            r: witness.r.clone(),
        };
        altered_s.s.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
        let inputs = build_inputs(&pk, &message, &altered_s).expect("altered preimage");
        assert!(!binary_relation_holds(&pk, &message, &altered_s));
        assert!(!coefficient_relation_holds(&inputs));

        let mut altered_r = witness;
        altered_r.r.set_entry(0, 0, PolyOverZ::from(2)).unwrap();
        let inputs = build_inputs(&pk, &message, &altered_r).expect("altered randomness");
        assert!(!binary_relation_holds(&pk, &message, &altered_r));
        assert!(!coefficient_relation_holds(&inputs));
    }
}
