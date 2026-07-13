//! The two-round issuing protocol:
//! `User --(c, pi_com)--> Signer --(x, s)--> User`.
//! Report: "The Commitment and the Protocol Layer" and "The Proof
//! Layer".

use crate::keys::{PublicKey, SecretKey};
use crate::proof_com::{prove_com, verify_com, ComProof};
use crate::tag_function::TagFunction;
use crate::util::{norm_eucl_sqrd, norm_inf};
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_tools::primitive::psf::PSF;

/// The first protocol message: the commitment `c` and the proof
/// `pi_com` of a short opening.
pub struct UserCommitMessage {
    pub c: MatPolynomialRingZq,
    pub proof: ComProof,
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
    let proof = prove_com(pk, m, &r, &c);
    (
        UserCommitMessage {
            c: c.clone(),
            proof,
        },
        UserState { m: m.clone(), r, c },
    )
}

/// Step 2: verifies `pi_com`, then samples `x <- [N]` and a preimage
/// for `f(x) + c`; returns `None` when the proof fails or the
/// preimage fails the norm bound (signer abort).
pub fn signer_respond<F: TagFunction>(
    pk: &PublicKey<F>,
    sk: &SecretKey,
    msg: &UserCommitMessage,
) -> Option<SignerResponse> {
    if !verify_com(pk, &msg.c, &msg.proof) {
        return None;
    }
    let upper = &pk.f.domain_size() + &Z::ONE;
    let x = Z::sample_uniform(Z::ONE, upper).unwrap();
    let target = &pk.f.eval(&x) + &msg.c;
    let s = pk.psf.samp_p(&pk.a, &sk.trapdoor, &target);
    if !pk.psf.check_domain(&s) {
        return None;
    }
    Some(SignerResponse { x, s })
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
        key_gen,
        tests::{toy_com_params, toy_psf},
        PublicKey,
    };
    use crate::tag_function::HashToRing;
    use qfall_math::rational::Q;
    use qfall_math::traits::MatrixDimensions;

    const D: i64 = 8;

    fn setup() -> (PublicKey<HashToRing>, SecretKey, MatPolyOverZ) {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "issue-test");
        let (pk, sk) = key_gen(
            f,
            psf,
            2,
            2,
            Q::from(3),
            Z::from(16),
            Z::from(2000),
            toy_com_params(),
        );
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
        assert!(signer_respond(&pk, &sk, &msg).is_none());
    }

    #[test]
    fn malformed_proof_makes_the_signer_abort() {
        let (pk, sk, m) = setup();
        let (mut msg, _) = user_commit(&pk, &m);
        msg.proof.z_m = MatPolyOverZ::new(pk.ck.b1.get_num_columns(), 2);
        assert!(signer_respond(&pk, &sk, &msg).is_none());
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
