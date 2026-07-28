//! Commitment-proof providers for the issuing protocol.
//! Report: "The Native Proof Layer".
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
