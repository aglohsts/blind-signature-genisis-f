//! Commitment-proof providers for the issuing protocol.
//! Report: "The Proof Layer" and "LaZer Integration Feasibility".

use crate::keys::PublicKey;
use crate::proof_com::{ComProof, prove_com, verify_com};
use crate::tag_function::TagFunction;
use qfall_math::integer::MatPolyOverZ;
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use std::convert::Infallible;

/// A proof provider for the commitment-opening relation.
pub trait CommitmentProofProvider<F: TagFunction> {
    type Proof;
    type Error;

    fn prove(
        &self,
        pk: &PublicKey<F>,
        m: &MatPolyOverZ,
        r: &MatPolyOverZ,
        c: &MatPolynomialRingZq,
    ) -> Result<Self::Proof, Self::Error>;

    fn verify(&self, pk: &PublicKey<F>, c: &MatPolynomialRingZq, proof: &Self::Proof) -> bool;
}

/// The native Fiat--Shamir proof provider.
pub struct FiatShamirCommitmentProofProvider;

impl<F: TagFunction> CommitmentProofProvider<F> for FiatShamirCommitmentProofProvider {
    type Proof = ComProof;
    type Error = Infallible;

    fn prove(
        &self,
        pk: &PublicKey<F>,
        m: &MatPolyOverZ,
        r: &MatPolyOverZ,
        c: &MatPolynomialRingZq,
    ) -> Result<Self::Proof, Self::Error> {
        Ok(prove_com(pk, m, r, c))
    }

    fn verify(&self, pk: &PublicKey<F>, c: &MatPolynomialRingZq, proof: &Self::Proof) -> bool {
        verify_com(pk, c, proof)
    }
}

#[cfg(feature = "lazer-ffi")]
mod lazer {
    use super::*;
    use crate::lazer_ffi::{self, Error};
    use qfall_math::integer::{PolyOverZ, Z};
    use qfall_math::traits::{GetCoefficient, MatrixDimensions, MatrixGetEntry};
    use qfall_tools::utils::common_moduli::new_anticyclic;

    /// An encoded proof for the fixed LaZer commitment profile.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct LazerD64CommitmentProof(Vec<u8>);

    impl LazerD64CommitmentProof {
        pub fn from_bytes(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    /// The fixed LaZer provider and its public-parameter seed.
    pub struct LazerD64CommitmentProofProvider {
        ppseed: [u8; 32],
    }

    impl LazerD64CommitmentProofProvider {
        pub const fn new(ppseed: [u8; 32]) -> Self {
            Self { ppseed }
        }
    }

    impl<F: TagFunction> CommitmentProofProvider<F> for LazerD64CommitmentProofProvider {
        type Proof = LazerD64CommitmentProof;
        type Error = Error;

        fn prove(
            &self,
            pk: &PublicKey<F>,
            m: &MatPolyOverZ,
            r: &MatPolyOverZ,
            c: &MatPolynomialRingZq,
        ) -> Result<Self::Proof, Self::Error> {
            let (matrix, statement) = statement_coefficients(pk, c)?;
            let witness = witness_coefficients(pk, m, r)?;
            lazer_ffi::prove(&matrix, &statement, &witness, &self.ppseed, None)
                .map(LazerD64CommitmentProof)
        }

        fn verify(&self, pk: &PublicKey<F>, c: &MatPolynomialRingZq, proof: &Self::Proof) -> bool {
            let Ok((matrix, statement)) = statement_coefficients(pk, c) else {
                return false;
            };
            lazer_ffi::verify(&matrix, &statement, &self.ppseed, proof.as_bytes()).unwrap_or(false)
        }
    }

    fn validate_profile<F: TagFunction>(pk: &PublicKey<F>) -> Result<(), Error> {
        let modulus = pk.f.modulus();
        if modulus.get_degree() != lazer_ffi::DEGREE as i64 {
            return Err(Error::ProfileMismatch("the ring degree must be 64"));
        }
        if modulus.get_q() != Z::from(257) {
            return Err(Error::ProfileMismatch("the ring modulus must be 257"));
        }
        let expected_modulus = new_anticyclic(lazer_ffi::DEGREE as i64, 257).unwrap();
        if modulus != &expected_modulus {
            return Err(Error::ProfileMismatch(
                "the polynomial modulus must be X^64 + 1",
            ));
        }
        if pk.ck.b1.get_num_rows() != 1
            || pk.ck.b1.get_num_columns() != 2
            || pk.ck.b2.get_num_rows() != 1
            || pk.ck.b2.get_num_columns() != 2
            || &pk.ck.b1.get_mod() != modulus
            || &pk.ck.b2.get_mod() != modulus
        {
            return Err(Error::ProfileMismatch(
                "the commitment key must have two message and two randomness columns",
            ));
        }
        if pk.beta_msg_sqrd != Z::from(16)
            || pk.beta_r_sqrd != Z::from(2000)
            || pk.com_params.witness_inf != 20
        {
            return Err(Error::ProfileMismatch(
                "the public witness bounds must match the generated profile",
            ));
        }
        Ok(())
    }

    fn statement_coefficients<F: TagFunction>(
        pk: &PublicKey<F>,
        c: &MatPolynomialRingZq,
    ) -> Result<(Vec<i64>, Vec<i64>), Error> {
        validate_profile(pk)?;
        if c.get_num_rows() != 1 || c.get_num_columns() != 1 || &c.get_mod() != pk.f.modulus() {
            return Err(Error::ProfileMismatch(
                "the commitment must be one element of the profile ring",
            ));
        }
        let mut matrix = Vec::with_capacity(lazer_ffi::MATRIX_COEFFICIENTS);
        append_ring_matrix(&mut matrix, &pk.ck.b1)?;
        append_ring_matrix(&mut matrix, &pk.ck.b2)?;
        let mut statement = Vec::with_capacity(lazer_ffi::STATEMENT_COEFFICIENTS);
        append_ring_matrix(&mut statement, c)?;
        Ok((matrix, statement))
    }

    fn witness_coefficients<F: TagFunction>(
        pk: &PublicKey<F>,
        m: &MatPolyOverZ,
        r: &MatPolyOverZ,
    ) -> Result<Vec<i64>, Error> {
        validate_profile(pk)?;
        if m.get_num_rows() != 2
            || m.get_num_columns() != 1
            || r.get_num_rows() != 2
            || r.get_num_columns() != 1
        {
            return Err(Error::ProfileMismatch(
                "the witness must have two message and two randomness polynomials",
            ));
        }
        let mut witness = Vec::with_capacity(lazer_ffi::WITNESS_COEFFICIENTS);
        append_witness_matrix(&mut witness, m)?;
        append_witness_matrix(&mut witness, r)?;
        Ok(witness)
    }

    fn append_ring_matrix(out: &mut Vec<i64>, matrix: &MatPolynomialRingZq) -> Result<(), Error> {
        append_integer_matrix(out, &matrix.get_representative_least_nonnegative_residue())
    }

    fn append_integer_matrix(out: &mut Vec<i64>, matrix: &MatPolyOverZ) -> Result<(), Error> {
        for row in 0..matrix.get_num_rows() {
            for column in 0..matrix.get_num_columns() {
                let polynomial: PolyOverZ = matrix.get_entry(row, column).unwrap();
                append_polynomial(out, &polynomial)?;
            }
        }
        Ok(())
    }

    fn append_witness_matrix(out: &mut Vec<i64>, matrix: &MatPolyOverZ) -> Result<(), Error> {
        for row in 0..matrix.get_num_rows() {
            let polynomial: PolyOverZ = matrix.get_entry(row, 0).unwrap();
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
pub use lazer::{LazerD64CommitmentProof, LazerD64CommitmentProofProvider};
