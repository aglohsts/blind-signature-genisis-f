//! Commitment-proof providers for the issuing protocol.
//! Report: "The Native Proof Layer" and "The Proof Layer on
//! LaZer".
//!
//! The issuing protocol talks to `Pi_com` through this trait, so the
//! native Fiat--Shamir proof and the LaZer proof are interchangeable.

use crate::keys::PublicKey;
use crate::proof_com::{self, Proof};
use crate::public_function::PublicFunction;
use qfall_math::integer::MatPolyOverZ;
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use std::convert::Infallible;

/// A proof provider for the commitment-opening relation
/// `c = B_1 m + B_2 r` with a short witness `(m, r)`.
pub trait CommitmentProofProvider<F: PublicFunction> {
    type Proof;
    type Error;

    fn prove(
        &self,
        public_key: &PublicKey<F>,
        message: &MatPolyOverZ,
        randomness: &MatPolyOverZ,
        commitment: &MatPolynomialRingZq,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify(
        &self,
        public_key: &PublicKey<F>,
        commitment: &MatPolynomialRingZq,
        proof: &Self::Proof,
    ) -> bool;
}

/// The native Fiat--Shamir proof provider.
pub struct FiatShamirProvider;

impl<F: PublicFunction> CommitmentProofProvider<F> for FiatShamirProvider {
    type Proof = Proof;
    type Error = Infallible;

    fn prove(
        &self,
        public_key: &PublicKey<F>,
        message: &MatPolyOverZ,
        randomness: &MatPolyOverZ,
        commitment: &MatPolynomialRingZq,
    ) -> Result<Proof, Infallible> {
        Ok(proof_com::prove(
            &public_key.commitment_key,
            &public_key.proof_parameters,
            message,
            randomness,
            commitment,
        ))
    }

    fn verify(
        &self,
        public_key: &PublicKey<F>,
        commitment: &MatPolynomialRingZq,
        proof: &Proof,
    ) -> bool {
        proof_com::verify(
            &public_key.commitment_key,
            &public_key.proof_parameters,
            commitment,
            proof,
        )
    }
}

#[cfg(feature = "lazer-ffi")]
mod lazer {
    use super::*;
    use crate::lazer_ffi::{self, Error, PROFILE_MESSAGE_BOUND_SQ, PROFILE_RANDOMNESS_BOUND_SQ};
    use qfall_math::integer::{PolyOverZ, Z};
    use qfall_math::traits::{GetCoefficient, MatrixDimensions, MatrixGetEntry};
    use qfall_tools::utils::common_moduli::new_anticyclic;

    /// An encoded proof for the fixed LaZer commitment profile.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct LazerProof(Vec<u8>);

    impl LazerProof {
        pub fn from_bytes(bytes: Vec<u8>) -> LazerProof {
            LazerProof(bytes)
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// The fixed LaZer provider and its public-parameter seed.
    pub struct LazerProvider {
        seed: [u8; 32],
    }

    impl LazerProvider {
        pub const fn new(seed: [u8; 32]) -> LazerProvider {
            LazerProvider { seed }
        }
    }

    impl<F: PublicFunction> CommitmentProofProvider<F> for LazerProvider {
        type Proof = LazerProof;
        type Error = Error;

        fn prove(
            &self,
            public_key: &PublicKey<F>,
            message: &MatPolyOverZ,
            randomness: &MatPolyOverZ,
            commitment: &MatPolynomialRingZq,
        ) -> Result<LazerProof, Error> {
            let (matrix, statement) = statement_coefficients(public_key, commitment)?;
            let witness = witness_coefficients(public_key, message, randomness)?;
            lazer_ffi::prove(&matrix, &statement, &witness, &self.seed, None).map(LazerProof)
        }

        fn verify(
            &self,
            public_key: &PublicKey<F>,
            commitment: &MatPolynomialRingZq,
            proof: &LazerProof,
        ) -> bool {
            let Ok((matrix, statement)) = statement_coefficients(public_key, commitment) else {
                return false;
            };
            lazer_ffi::verify(&matrix, &statement, &self.seed, proof.as_bytes()).unwrap_or(false)
        }
    }

    /// Checks that the public key matches the generated profile. The
    /// profile is fixed at code-generation time, so a mismatch cannot
    /// be repaired at run time.
    fn validate_profile<F: PublicFunction>(public_key: &PublicKey<F>) -> Result<(), Error> {
        let modulus = public_key.function.modulus();
        let expected = new_anticyclic(lazer_ffi::DEGREE as i64, lazer_ffi::MODULUS).unwrap();
        if modulus != &expected {
            return Err(Error::ProfileMismatch(
                "the ring must be Z_q[X]/(X^64 + 1) with the profile modulus",
            ));
        }
        let key = &public_key.commitment_key;
        if key.b1.get_num_rows() != 1
            || key.b1.get_num_columns() != 2
            || key.b2.get_num_rows() != 1
            || key.b2.get_num_columns() != 2
            || &key.b1.get_mod() != modulus
            || &key.b2.get_mod() != modulus
        {
            return Err(Error::ProfileMismatch(
                "the commitment key must have two message and two randomness columns",
            ));
        }
        if public_key.message_bound_sqrd > Z::from(PROFILE_MESSAGE_BOUND_SQ)
            || key.randomness_bound_sqrd() > Z::from(PROFILE_RANDOMNESS_BOUND_SQ)
        {
            return Err(Error::ProfileMismatch(
                "the public witness bounds exceed the generated profile",
            ));
        }
        if public_key.proof_parameters.witness_inf > lazer_ffi::PROFILE_WITNESS_INF {
            return Err(Error::ProfileMismatch(
                "the witness infinity bound exceeds the generated profile",
            ));
        }
        Ok(())
    }

    fn statement_coefficients<F: PublicFunction>(
        public_key: &PublicKey<F>,
        commitment: &MatPolynomialRingZq,
    ) -> Result<(Vec<i64>, Vec<i64>), Error> {
        validate_profile(public_key)?;
        if commitment.get_num_rows() != 1
            || commitment.get_num_columns() != 1
            || &commitment.get_mod() != public_key.function.modulus()
        {
            return Err(Error::ProfileMismatch(
                "the commitment must be one element of the profile ring",
            ));
        }
        let mut matrix = Vec::with_capacity(lazer_ffi::MATRIX_COEFFICIENTS);
        append_ring_matrix(&mut matrix, &public_key.commitment_key.b1)?;
        append_ring_matrix(&mut matrix, &public_key.commitment_key.b2)?;
        let mut statement = Vec::with_capacity(lazer_ffi::STATEMENT_COEFFICIENTS);
        append_ring_matrix(&mut statement, commitment)?;
        Ok((matrix, statement))
    }

    fn witness_coefficients<F: PublicFunction>(
        public_key: &PublicKey<F>,
        message: &MatPolyOverZ,
        randomness: &MatPolyOverZ,
    ) -> Result<Vec<i64>, Error> {
        validate_profile(public_key)?;
        if message.get_num_rows() != 2
            || message.get_num_columns() != 1
            || randomness.get_num_rows() != 2
            || randomness.get_num_columns() != 1
        {
            return Err(Error::ProfileMismatch(
                "the witness must have two message and two randomness polynomials",
            ));
        }
        let mut witness = Vec::with_capacity(lazer_ffi::WITNESS_COEFFICIENTS);
        append_witness_vector(&mut witness, message)?;
        append_witness_vector(&mut witness, randomness)?;
        Ok(witness)
    }

    fn append_ring_matrix(out: &mut Vec<i64>, matrix: &MatPolynomialRingZq) -> Result<(), Error> {
        let integers = matrix.get_representative_least_nonnegative_residue();
        for row in 0..integers.get_num_rows() {
            for column in 0..integers.get_num_columns() {
                let polynomial: PolyOverZ = integers.get_entry(row, column).unwrap();
                append_polynomial(out, &polynomial)?;
            }
        }
        Ok(())
    }

    fn append_witness_vector(out: &mut Vec<i64>, vector: &MatPolyOverZ) -> Result<(), Error> {
        for row in 0..vector.get_num_rows() {
            let polynomial: PolyOverZ = vector.get_entry(row, 0).unwrap();
            if polynomial.get_degree() >= lazer_ffi::DEGREE as i64 {
                return Err(Error::ProfileMismatch(
                    "witness polynomials must fit the profile ring degree",
                ));
            }
            append_polynomial(out, &polynomial)?;
        }
        Ok(())
    }

    fn append_polynomial(out: &mut Vec<i64>, polynomial: &PolyOverZ) -> Result<(), Error> {
        for index in 0..lazer_ffi::DEGREE as i64 {
            let coefficient: Z = polynomial.get_coeff(index).unwrap();
            out.push(i64::try_from(&coefficient).map_err(|_| Error::CoefficientOutOfRange)?);
        }
        Ok(())
    }
}

#[cfg(feature = "lazer-ffi")]
pub use lazer::{LazerProof, LazerProvider};
