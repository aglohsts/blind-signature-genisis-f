//! The LaZer provider for the final-signature relation `R_sig`.
//! Report: "The Proof Layer on LaZer".
//!
//! The relation
//!
//! ```text
//! A s = f(kappa, mu, xi) + B_1 m + B_2 r
//! ```
//!
//! is rewritten with the algebraic function
//! `f(kappa, mu, xi) = kappa xi + G enc(mu)` as
//!
//! ```text
//! A s - kappa xi - B_2 r - G enc(mu) - B_1 m = 0,
//! ```
//!
//! which is linear in the hidden values. The bounded witness is the
//! concatenation `(s, xi, r)`; `enc(mu)` is the binary witness; and the
//! public message `m` moves into the constant offset. This is the step
//! the hash-based function cannot take, because `H(sep|kappa|mu|xi)`
//! is not linear in `mu` and `xi`.

use super::{
    FinalSignatureProofProvider, ModuleLweWitness, fits_ring_degree, relation_holds,
};
use crate::keys::PublicKey;
use crate::lazer_ffi::{self, Error};
use crate::module_lwe::ModuleLweEncoding;
use crate::public_function::PublicFunction;
use qfall_math::integer::{MatPolyOverZ, MatZ, PolyOverZ, Z};
use qfall_math::integer_mod_q::{MatPolynomialRingZq, MatZq};
use qfall_math::rational::Q;
use qfall_math::traits::{GetCoefficient, MatrixDimensions, MatrixGetEntry};
use qfall_tools::utils::common_moduli::new_anticyclic;

/// The public part of the coefficient-level statement.
pub(crate) struct Statement {
    pub(crate) linear: Vec<i64>,
    pub(crate) tag_matrix: Vec<i64>,
    pub(crate) offset: Vec<i64>,
}

/// The hidden part, split the way the profile expects it.
pub(crate) struct Witness {
    pub(crate) bounded: Vec<i64>,
    pub(crate) tag: Vec<i64>,
}

/// An encoded proof for the fixed LaZer final-signature profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LazerSignatureProof(Vec<u8>);

impl LazerSignatureProof {
    pub fn from_bytes(bytes: Vec<u8>) -> LazerSignatureProof {
        LazerSignatureProof(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The fixed LaZer final-signature provider and its public-parameter
/// seed.
pub struct LazerSignatureProvider {
    seed: [u8; 32],
}

impl LazerSignatureProvider {
    pub const fn new(seed: [u8; 32]) -> LazerSignatureProvider {
        LazerSignatureProvider { seed }
    }
}

impl FinalSignatureProofProvider<ModuleLweEncoding> for LazerSignatureProvider {
    type Witness = ModuleLweWitness;
    type Proof = LazerSignatureProof;
    type Error = Error;

    fn prove(
        &self,
        public_key: &PublicKey<ModuleLweEncoding>,
        message: &MatPolyOverZ,
        witness: &ModuleLweWitness,
    ) -> Result<LazerSignatureProof, Error> {
        validate_bounds(public_key)?;
        let statement = build_statement(public_key, message)?;
        let inputs = build_witness(witness)?;
        // A witness that misses the relation would only produce a proof
        // that fails to verify, so it is reported as an error here.
        if !relation_holds(public_key, message, witness) {
            return Err(Error::InvalidInput);
        }
        lazer_ffi::prove_final_signature(
            &statement.linear,
            &statement.tag_matrix,
            &statement.offset,
            &inputs.bounded,
            &inputs.tag,
            &self.seed,
            None,
        )
        .map(LazerSignatureProof)
    }

    fn verify(
        &self,
        public_key: &PublicKey<ModuleLweEncoding>,
        message: &MatPolyOverZ,
        proof: &LazerSignatureProof,
    ) -> bool {
        if validate_bounds(public_key).is_err() {
            return false;
        }
        // The message is public, so the verifier checks its bound
        // itself instead of proving it.
        if crate::util::norm_eucl_sqrd(message, lazer_ffi::DEGREE as i64)
            > public_key.message_bound_sqrd
        {
            return false;
        }
        let Ok(statement) = build_statement(public_key, message) else {
            return false;
        };
        lazer_ffi::verify_final_signature(
            &statement.linear,
            &statement.tag_matrix,
            &statement.offset,
            &self.seed,
            proof.as_bytes(),
        )
        .unwrap_or(false)
    }
}

/// Serialises `[A | -kappa | -B_2]`, `-G`, and `-B_1 m`.
pub(crate) fn build_statement(
    public_key: &PublicKey<ModuleLweEncoding>,
    message: &MatPolyOverZ,
) -> Result<Statement, Error> {
    validate_layout(public_key, message)?;

    let mut linear = Vec::with_capacity(lazer_ffi::LINEAR_COEFFICIENTS);
    append_ring_matrix(&mut linear, &public_key.a, 1)?;
    append_ring_matrix(&mut linear, &public_key.function_key, -1)?;
    append_ring_matrix(&mut linear, &public_key.commitment_key.b2, -1)?;

    let mut tag_matrix = Vec::with_capacity(lazer_ffi::TAG_MATRIX_COEFFICIENTS);
    append_mod_q_matrix(&mut tag_matrix, public_key.function.encoding_matrix(), -1)?;

    let message_ring = MatPolynomialRingZq::from((message, public_key.function.modulus()));
    let message_image = &public_key.commitment_key.b1 * &message_ring;
    let mut offset = Vec::with_capacity(lazer_ffi::OFFSET_COEFFICIENTS);
    append_ring_matrix(&mut offset, &message_image, -1)?;

    Ok(Statement {
        linear,
        tag_matrix,
        offset,
    })
}

/// Serialises the bounded block `(s, xi, r)` and the binary `enc(mu)`.
pub(crate) fn build_witness(witness: &ModuleLweWitness) -> Result<Witness, Error> {
    validate_witness_layout(witness)?;

    let mut bounded = Vec::with_capacity(lazer_ffi::FINAL_WITNESS_COEFFICIENTS);
    append_integer_matrix(&mut bounded, &witness.preimage, 1)?;
    append_integer_matrix(&mut bounded, &witness.function_randomness, 1)?;
    append_integer_matrix(&mut bounded, &witness.randomness, 1)?;

    let mut tag = Vec::with_capacity(lazer_ffi::TAG_COEFFICIENTS);
    append_integer_entries(&mut tag, &witness.encoding, 1)?;

    Ok(Witness { bounded, tag })
}

fn validate_layout(
    public_key: &PublicKey<ModuleLweEncoding>,
    message: &MatPolyOverZ,
) -> Result<(), Error> {
    let expected = new_anticyclic(lazer_ffi::DEGREE as i64, lazer_ffi::MODULUS).unwrap();
    let modulus = public_key.function.modulus();
    if modulus != &expected {
        return Err(Error::ProfileMismatch(
            "the final-signature ring must be Z_q[X]/(X^64 + 1)",
        ));
    }
    if &public_key.a.get_mod() != modulus
        || &public_key.commitment_key.b1.get_mod() != modulus
        || &public_key.commitment_key.b2.get_mod() != modulus
        || &public_key.function_key.get_mod() != modulus
    {
        return Err(Error::ProfileMismatch(
            "the final-signature matrices must use the statement ring",
        ));
    }
    let encoding_matrix = public_key.function.encoding_matrix();
    if (public_key.a.get_num_rows(), public_key.a.get_num_columns())
        != (1, lazer_ffi::PREIMAGE_COLUMNS as i64)
        || (
            public_key.function_key.get_num_rows(),
            public_key.function_key.get_num_columns(),
        ) != (1, lazer_ffi::FUNCTION_RANDOMNESS_COLUMNS as i64)
        || (
            public_key.commitment_key.b1.get_num_rows(),
            public_key.commitment_key.b1.get_num_columns(),
        ) != (1, 2)
        || (
            public_key.commitment_key.b2.get_num_rows(),
            public_key.commitment_key.b2.get_num_columns(),
        ) != (1, lazer_ffi::RANDOMNESS_COLUMNS as i64)
        || (
            encoding_matrix.get_num_rows(),
            encoding_matrix.get_num_columns(),
        ) != (
            lazer_ffi::DEGREE as i64,
            lazer_ffi::TAG_COEFFICIENTS as i64,
        )
        || public_key.function.bits() != lazer_ffi::TAG_COEFFICIENTS as i64
        || public_key.function.randomness_length()
            != lazer_ffi::FUNCTION_RANDOMNESS_COLUMNS as i64
    {
        return Err(Error::ProfileMismatch(
            "the final-signature dimensions must match the generated profile",
        ));
    }
    if (message.get_num_rows(), message.get_num_columns())
        != (public_key.commitment_key.b1.get_num_columns(), 1)
        || !fits_ring_degree(message, lazer_ffi::DEGREE as i64)
    {
        return Err(Error::ProfileMismatch(
            "the final-signature statement must match the profile layout",
        ));
    }
    Ok(())
}

fn validate_witness_layout(witness: &ModuleLweWitness) -> Result<(), Error> {
    if (
        witness.preimage.get_num_rows(),
        witness.preimage.get_num_columns(),
    ) != (lazer_ffi::PREIMAGE_COLUMNS as i64, 1)
        || (
            witness.function_randomness.get_num_rows(),
            witness.function_randomness.get_num_columns(),
        ) != (lazer_ffi::FUNCTION_RANDOMNESS_COLUMNS as i64, 1)
        || (
            witness.randomness.get_num_rows(),
            witness.randomness.get_num_columns(),
        ) != (lazer_ffi::RANDOMNESS_COLUMNS as i64, 1)
        || (
            witness.encoding.get_num_rows(),
            witness.encoding.get_num_columns(),
        ) != (lazer_ffi::TAG_COEFFICIENTS as i64, 1)
        || !fits_ring_degree(&witness.preimage, lazer_ffi::DEGREE as i64)
        || !fits_ring_degree(&witness.function_randomness, lazer_ffi::DEGREE as i64)
        || !fits_ring_degree(&witness.randomness, lazer_ffi::DEGREE as i64)
    {
        return Err(Error::ProfileMismatch(
            "the final-signature witness must match the profile layout",
        ));
    }
    Ok(())
}

/// The generated profile fixes every norm bound, so a public key with
/// looser bounds cannot use it.
fn validate_bounds(public_key: &PublicKey<ModuleLweEncoding>) -> Result<(), Error> {
    if public_key.message_bound_sqrd > Z::from(lazer_ffi::PROFILE_MESSAGE_BOUND_SQ)
        || public_key.commitment_key.randomness_bound_sqrd()
            > Z::from(lazer_ffi::PROFILE_RANDOMNESS_BOUND_SQ)
        || public_key.function.randomness_bound_sqrd()
            > Z::from(lazer_ffi::PROFILE_FUNCTION_RANDOMNESS_BOUND_SQ)
        || public_key.sampler.preimage_bound_sqrd()
            > Q::from(lazer_ffi::PROFILE_PREIMAGE_BOUND_SQ)
        || public_key.sampler.modulus() != public_key.function.modulus()
    {
        return Err(Error::ProfileMismatch(
            "the final-signature bounds must match the generated profile",
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

fn append_integer_entries(out: &mut Vec<i64>, matrix: &MatZ, sign: i64) -> Result<(), Error> {
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
