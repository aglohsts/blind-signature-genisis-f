//! Commitment-proof backends for the issuing protocol.
//! Report: "The Proof Layer" and "LaZer Integration Feasibility".

use crate::keys::PublicKey;
use crate::proof_com::{prove_com, verify_com, ComProof};
use crate::tag_function::TagFunction;
use qfall_math::integer::MatPolyOverZ;
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use std::convert::Infallible;

/// A proof backend for the commitment-opening relation.
pub trait CommitmentProofBackend<F: TagFunction> {
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

/// The native Fiat--Shamir proof backend.
pub struct FiatShamirBackend;

impl<F: TagFunction> CommitmentProofBackend<F> for FiatShamirBackend {
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
