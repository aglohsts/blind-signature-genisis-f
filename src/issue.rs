//! The one-round issuing protocol.
//! Report: "Issuing protocol".

use crate::commitment_proof::CommitmentProofProvider;
use crate::keys::{PublicKey, SecretKey};
use crate::public_function::PublicFunction;
use crate::util::norm_eucl_sqrd;
use qfall_math::integer::MatPolyOverZ;
use qfall_math::integer_mod_q::MatPolynomialRingZq;

/// The request sent by the user. The proof type is fixed by the
/// commitment-proof provider in use.
pub struct Request<P> {
    pub commitment: MatPolynomialRingZq,
    pub proof: P,
}

/// What the user keeps between the two messages.
pub struct UserState {
    pub message: MatPolyOverZ,
    pub randomness: MatPolyOverZ,
    pub commitment: MatPolynomialRingZq,
}

/// What the signer sends back.
pub struct Response<F: PublicFunction> {
    pub function_input: F::Input,
    pub function_randomness: F::Randomness,
    pub preimage: MatPolyOverZ,
}

/// Step 1: the user samples r, commits, proves knowledge of the
/// opening, and keeps its state.
pub fn user_request<F, P>(
    public_key: &PublicKey<F>,
    message: &MatPolyOverZ,
    provider: &P,
) -> Result<(Request<P::Proof>, UserState), P::Error>
where
    F: PublicFunction,
    P: CommitmentProofProvider<F>,
{
    let degree = public_key.function.modulus().get_degree();
    assert!(
        norm_eucl_sqrd(message, degree) <= public_key.message_bound_sqrd,
        "the message is outside the message space",
    );
    let randomness = public_key.commitment_key.sample_randomness();
    let commitment = public_key.commitment_key.commit(message, &randomness);
    let proof = provider.prove(public_key, message, &randomness, &commitment)?;
    let state = UserState {
        message: message.clone(),
        randomness,
        commitment: commitment.clone(),
    };
    Ok((Request { commitment, proof }, state))
}

/// Step 2: the signer verifies the proof, then samples mu and xi and a
/// short preimage for the target f(kappa, mu, xi) + c. It returns None
/// when the proof fails or the preimage misses the norm bound.
pub fn signer_respond<F, P>(
    public_key: &PublicKey<F>,
    secret_key: &SecretKey,
    request: &Request<P::Proof>,
    provider: &P,
) -> Option<Response<F>>
where
    F: PublicFunction,
    P: CommitmentProofProvider<F>,
{
    if !provider.verify(public_key, &request.commitment, &request.proof) {
        return None;
    }
    let function_input = public_key.function.sample_input();
    let function_randomness = public_key.function.sample_randomness();
    let target = &public_key.function.eval(
        &public_key.function_key,
        &function_input,
        &function_randomness,
    ) + &request.commitment;
    let preimage = public_key.sampler.samp_p(&secret_key.trapdoor, &target);
    if !public_key.sampler.check_domain(&preimage) {
        return None;
    }
    Some(Response {
        function_input,
        function_randomness,
        preimage,
    })
}

/// Step 3: the user checks the response.
pub fn user_check<F: PublicFunction>(
    public_key: &PublicKey<F>,
    state: &UserState,
    response: &Response<F>,
) -> bool {
    // The norm bound comes first because the reused f_a asserts it.
    public_key
        .function
        .contains_input(&response.function_input)
        && public_key
            .function
            .contains_randomness(&response.function_randomness)
        && public_key.sampler.check_domain(&response.preimage)
        && public_key.sampler.f_a(&public_key.a, &response.preimage)
            == &public_key.function.eval(
                &public_key.function_key,
                &response.function_input,
                &response.function_randomness,
            ) + &state.commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment_proof::FiatShamirProvider;
    use crate::hash_to_ring::HashToRing;
    use crate::keys::{
        key_gen,
        tests::{toy_function, toy_parameters, toy_sampler},
    };
    use qfall_math::integer::Z;

    const D: i64 = 8;

    fn setup() -> (PublicKey<HashToRing>, SecretKey, MatPolyOverZ) {
        let sampler = toy_sampler();
        let function = toy_function(&sampler, "issue-test");
        let (public_key, secret_key) = key_gen(function, sampler, toy_parameters());
        let message = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        (public_key, secret_key, message)
    }

    #[test]
    fn honest_run_passes_the_user_check() {
        let (public_key, secret_key, message) = setup();
        let (request, state) =
            user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
        let response = signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider)
            .expect("signer aborted");
        assert!(user_check(&public_key, &state, &response));
    }

    /// After an honest run the user holds a witness for the final
    /// relation A s = f(kappa, mu, xi) + B_1 m + B_2 r.
    #[test]
    fn finalisation_identity_holds() {
        let (public_key, secret_key, message) = setup();
        let (request, state) =
            user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
        let response = signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider)
            .expect("signer aborted");
        let left = public_key.sampler.f_a(&public_key.a, &response.preimage);
        let right = &public_key.function.eval(
            &public_key.function_key,
            &response.function_input,
            &response.function_randomness,
        ) + &public_key
            .commitment_key
            .commit(&state.message, &state.randomness);
        assert_eq!(right, left);
    }

    #[test]
    fn changed_function_input_fails_the_user_check() {
        let (public_key, secret_key, message) = setup();
        let (request, state) =
            user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
        let mut response = signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider)
            .expect("signer aborted");
        response.function_input = &response.function_input + &Z::ONE;
        assert!(!user_check(&public_key, &state, &response));
    }

    #[test]
    fn changed_function_randomness_fails_the_user_check() {
        let (public_key, secret_key, message) = setup();
        let (request, state) =
            user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
        let mut response = signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider)
            .expect("signer aborted");
        response.function_randomness = &response.function_randomness + &Z::ONE;
        assert!(!user_check(&public_key, &state, &response));
    }

    #[test]
    fn changed_preimage_fails_the_user_check() {
        let (public_key, secret_key, message) = setup();
        let (request, state) =
            user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
        let mut response = signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider)
            .expect("signer aborted");
        response.preimage = &response.preimage + &response.preimage;
        assert!(!user_check(&public_key, &state, &response));
    }

    #[test]
    fn an_invalid_proof_makes_the_signer_abort() {
        let (public_key, secret_key, message) = setup();
        let (mut request, _) =
            user_request(&public_key, &message, &FiatShamirProvider).expect("proof");
        request.proof.message_response =
            &request.proof.message_response + &request.proof.message_response;
        assert!(
            signer_respond(&public_key, &secret_key, &request, &FiatShamirProvider).is_none()
        );
    }

    #[test]
    #[should_panic(expected = "outside the message space")]
    fn oversized_message_is_rejected() {
        let (public_key, _, _) = setup();
        let big = MatPolyOverZ::sample_uniform(2, 1, D - 1, 100, 200).unwrap();
        let _ = user_request(&public_key, &big, &FiatShamirProvider);
    }
}
