//! The two-round issuing protocol:
//! `User --(c, pi_com)--> Signer --(x, s)--> User`.
//! Report: "The Commitment and the Protocol Layer" and "The Proof
//! Layer".

use crate::commitment_proof::{CommitmentProofProvider, FiatShamirCommitmentProofProvider};
use crate::keys::{PublicKey, SecretKey};
use crate::proof_com::ComProof;
use crate::tag_function::TagFunction;
use crate::util::{norm_eucl_sqrd, norm_inf};
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_tools::primitive::psf::PSF;
use std::fmt;

/// Errors that make the signer abort the issuing protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueError {
    InvalidCommitmentProof,
    TagSamplingFailed,
    TagOutOfRange,
    PreimageSamplingFailed,
    InvalidPreimage,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCommitmentProof => write!(f, "the commitment proof is invalid"),
            Self::TagSamplingFailed => write!(f, "tag sampling failed"),
            Self::TagOutOfRange => write!(f, "the sampled tag is outside the public domain"),
            Self::PreimageSamplingFailed => write!(f, "preimage sampling failed"),
            Self::InvalidPreimage => write!(f, "the sampled preimage is invalid"),
        }
    }
}

impl std::error::Error for IssueError {}

/// Supplies a tag for the signer response.
pub trait TagSampler {
    fn sample_tag(&self, domain_size: &Z) -> Result<Z, IssueError>;
}

/// Samples tags uniformly from the public domain.
pub struct RandomTagSampler;

impl TagSampler for RandomTagSampler {
    fn sample_tag(&self, domain_size: &Z) -> Result<Z, IssueError> {
        Z::sample_uniform(Z::ONE, domain_size + &Z::ONE).map_err(|_| IssueError::TagSamplingFailed)
    }
}

/// Supplies a conditioned preimage for the signer response.
pub trait PreimageSampler {
    fn sample<F: TagFunction>(
        &self,
        pk: &PublicKey<F>,
        sk: &SecretKey,
        target: &MatPolynomialRingZq,
    ) -> Result<MatPolyOverZ, IssueError>;
}

/// Uses qFALL's conditioned GPV preimage sampler.
pub struct QfallPreimageSampler;

impl PreimageSampler for QfallPreimageSampler {
    fn sample<F: TagFunction>(
        &self,
        pk: &PublicKey<F>,
        sk: &SecretKey,
        target: &MatPolynomialRingZq,
    ) -> Result<MatPolyOverZ, IssueError> {
        Ok(pk.psf.samp_p(&pk.a, &sk.trapdoor, target))
    }
}

/// The first protocol message: the commitment `c` and the proof
/// `pi_com` of a short opening.
pub struct UserCommitMessage<P = ComProof> {
    pub c: MatPolynomialRingZq,
    pub proof: P,
}

/// The user state kept between the two rounds.
pub struct UserState {
    pub m: MatPolyOverZ,
    pub r: MatPolyOverZ,
    pub c: MatPolynomialRingZq,
}

/// The second protocol message: the tag `x` and the preimage `s`.
pub struct SignerResponse {
    pub x: Z,
    pub s: MatPolyOverZ,
}

/// Step 1: checks the message space, samples `r <- chi_r`, commits,
/// and proves knowledge of the opening.
pub fn user_commit<F: TagFunction>(
    pk: &PublicKey<F>,
    m: &MatPolyOverZ,
) -> (UserCommitMessage, UserState) {
    user_commit_with_provider(pk, m, &FiatShamirCommitmentProofProvider)
        .expect("the native provider is infallible")
}

/// Step 1 with an explicit commitment-proof provider.
pub fn user_commit_with_provider<F: TagFunction, P: CommitmentProofProvider<F>>(
    pk: &PublicKey<F>,
    m: &MatPolyOverZ,
    provider: &P,
) -> Result<(UserCommitMessage<P::Proof>, UserState), P::Error> {
    let degree = pk.f.modulus().get_degree();
    assert!(
        norm_eucl_sqrd(m, degree) <= pk.beta_msg_sqrd
            && norm_inf(m, degree) <= pk.com_params.witness_inf,
        "the message is outside the message or proof bounds",
    );
    let r = loop {
        let candidate = pk.ck.sample_randomness(&pk.s_r);
        if norm_eucl_sqrd(&candidate, degree) <= pk.beta_r_sqrd
            && norm_inf(&candidate, degree) <= pk.com_params.witness_inf
        {
            break candidate;
        }
    };
    let c = pk.ck.commit(m, &r);
    let proof = provider.prove(pk, m, &r, &c)?;
    Ok((
        UserCommitMessage {
            c: c.clone(),
            proof,
        },
        UserState { m: m.clone(), r, c },
    ))
}

/// Step 2: verifies `pi_com`, then samples `x <- [N]` and a preimage
/// for `f(x) + c`.
pub fn signer_respond<F: TagFunction>(
    pk: &PublicKey<F>,
    sk: &SecretKey,
    msg: &UserCommitMessage,
) -> Result<SignerResponse, IssueError> {
    signer_respond_with_provider(pk, sk, msg, &FiatShamirCommitmentProofProvider)
}

/// Step 2 with an explicit preimage sampler.
pub fn signer_respond_with_sampler<F: TagFunction, S: PreimageSampler>(
    pk: &PublicKey<F>,
    sk: &SecretKey,
    msg: &UserCommitMessage,
    sampler: &S,
) -> Result<SignerResponse, IssueError> {
    signer_respond_with_components(
        pk,
        sk,
        msg,
        &FiatShamirCommitmentProofProvider,
        &RandomTagSampler,
        sampler,
    )
}

/// Step 2 with an explicit commitment-proof provider.
pub fn signer_respond_with_provider<F: TagFunction, P: CommitmentProofProvider<F>>(
    pk: &PublicKey<F>,
    sk: &SecretKey,
    msg: &UserCommitMessage<P::Proof>,
    provider: &P,
) -> Result<SignerResponse, IssueError> {
    signer_respond_with_components(
        pk,
        sk,
        msg,
        provider,
        &RandomTagSampler,
        &QfallPreimageSampler,
    )
}

/// Step 2 with explicit proof, tag and preimage components.
pub fn signer_respond_with_components<
    F: TagFunction,
    P: CommitmentProofProvider<F>,
    T: TagSampler,
    S: PreimageSampler,
>(
    pk: &PublicKey<F>,
    sk: &SecretKey,
    msg: &UserCommitMessage<P::Proof>,
    provider: &P,
    tag_sampler: &T,
    preimage_sampler: &S,
) -> Result<SignerResponse, IssueError> {
    if !verify_user_commit_with_provider(pk, msg, provider) {
        return Err(IssueError::InvalidCommitmentProof);
    }
    let domain_size = pk.f.domain_size();
    let x = tag_sampler.sample_tag(&domain_size)?;
    if x < Z::ONE || x > domain_size {
        return Err(IssueError::TagOutOfRange);
    }
    let target = &pk.f.eval(&x) + &msg.c;
    let s = preimage_sampler.sample(pk, sk, &target)?;
    if !pk.psf.check_domain(&s) {
        return Err(IssueError::InvalidPreimage);
    }
    if pk.psf.f_a(&pk.a, &s) != target {
        return Err(IssueError::InvalidPreimage);
    }
    Ok(SignerResponse { x, s })
}

/// Verifies the first protocol message with an explicit proof provider.
pub fn verify_user_commit_with_provider<F: TagFunction, P: CommitmentProofProvider<F>>(
    pk: &PublicKey<F>,
    msg: &UserCommitMessage<P::Proof>,
    provider: &P,
) -> bool {
    provider.verify(pk, &msg.c, &msg.proof)
}

/// Step 3: checks the tag, the equation `A * s = f(x) + c`, and the
/// norm bound.
pub fn user_check<F: TagFunction>(
    pk: &PublicKey<F>,
    st: &UserState,
    resp: &SignerResponse,
) -> bool {
    // The norm bound comes first: the reused f_a asserts its domain
    // bound internally. Report: "The Commitment and the Protocol
    // Layer".
    resp.x >= Z::ONE
        && resp.x <= pk.f.domain_size()
        && pk.psf.check_domain(&resp.s)
        && pk.psf.f_a(&pk.a, &resp.s) == &pk.f.eval(&resp.x) + &st.c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{
        PublicKey, key_gen,
        tests::{toy_key_gen_params, toy_psf},
    };
    use crate::tag_function::HashToRing;
    use qfall_math::traits::MatrixDimensions;

    const D: i64 = 8;

    struct FixedTagSampler(Z);

    impl TagSampler for FixedTagSampler {
        fn sample_tag(&self, _domain_size: &Z) -> Result<Z, IssueError> {
            Ok(self.0.clone())
        }
    }

    struct FixedPreimageSampler(MatPolyOverZ);

    impl PreimageSampler for FixedPreimageSampler {
        fn sample<F: TagFunction>(
            &self,
            _pk: &PublicKey<F>,
            _sk: &SecretKey,
            _target: &MatPolynomialRingZq,
        ) -> Result<MatPolyOverZ, IssueError> {
            Ok(self.0.clone())
        }
    }

    fn setup() -> (PublicKey<HashToRing>, SecretKey, MatPolyOverZ) {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "issue-test");
        let (pk, sk) = key_gen(f, psf, toy_key_gen_params(2000));
        let m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        (pk, sk, m)
    }

    #[test]
    fn honest_run_passes() {
        let (pk, sk, m) = setup();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        assert!(user_check(&pk, &st, &resp));
    }

    #[test]
    fn finalisation_identity_holds() {
        let (pk, sk, m) = setup();
        let (msg, st) = user_commit(&pk, &m);
        let resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        let lhs = pk.psf.f_a(&pk.a, &resp.s);
        let rhs = &pk.f.eval(&resp.x) + &pk.ck.commit(&st.m, &st.r);
        assert_eq!(rhs, lhs);
    }

    #[test]
    fn tampered_tag_fails() {
        let (pk, sk, m) = setup();
        let (msg, st) = user_commit(&pk, &m);
        let mut resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        resp.x = &resp.x + &Z::ONE;
        assert!(!user_check(&pk, &st, &resp));
    }

    #[test]
    fn tampered_preimage_fails() {
        let (pk, sk, m) = setup();
        let (msg, st) = user_commit(&pk, &m);
        let mut resp = signer_respond(&pk, &sk, &msg).expect("signer aborted");
        resp.s = &resp.s + &resp.s;
        assert!(!user_check(&pk, &st, &resp));
    }

    #[test]
    fn invalid_proof_makes_the_signer_abort() {
        let (pk, sk, m) = setup();
        let (mut msg, _) = user_commit(&pk, &m);
        msg.proof.z_m = &msg.proof.z_m + &msg.proof.z_m;
        assert!(matches!(
            signer_respond(&pk, &sk, &msg),
            Err(IssueError::InvalidCommitmentProof)
        ));
    }

    #[test]
    fn malformed_proof_makes_the_signer_abort() {
        let (pk, sk, m) = setup();
        let (mut msg, _) = user_commit(&pk, &m);
        msg.proof.z_m = MatPolyOverZ::new(pk.ck.b1.get_num_columns(), 2);
        assert!(matches!(
            signer_respond(&pk, &sk, &msg),
            Err(IssueError::InvalidCommitmentProof)
        ));
    }

    #[test]
    fn injected_signer_components_must_match_the_public_target() {
        let (pk, sk, m) = setup();
        let (msg, _) = user_commit(&pk, &m);
        let zero = MatPolyOverZ::new(pk.a.get_num_columns(), 1);
        assert!(matches!(
            signer_respond_with_components(
                &pk,
                &sk,
                &msg,
                &FiatShamirCommitmentProofProvider,
                &FixedTagSampler(Z::ZERO),
                &FixedPreimageSampler(zero.clone()),
            ),
            Err(IssueError::TagOutOfRange)
        ));
        assert!(matches!(
            signer_respond_with_components(
                &pk,
                &sk,
                &msg,
                &FiatShamirCommitmentProofProvider,
                &FixedTagSampler(Z::ONE),
                &FixedPreimageSampler(zero),
            ),
            Err(IssueError::InvalidPreimage)
        ));
    }

    #[test]
    fn commitment_randomness_satisfies_public_bounds() {
        let (pk, _, m) = setup();
        let (_, state) = user_commit(&pk, &m);
        let degree = pk.f.modulus().get_degree();
        assert!(norm_eucl_sqrd(&state.r, degree) <= pk.beta_r_sqrd);
        assert!(norm_inf(&state.r, degree) <= pk.com_params.witness_inf);
    }

    #[test]
    #[should_panic(expected = "outside the message or proof bounds")]
    fn oversized_message_rejected() {
        let (pk, _, _) = setup();
        let big_m = MatPolyOverZ::sample_uniform(2, 1, D - 1, 100, 200).unwrap();
        user_commit(&pk, &big_m);
    }
}
