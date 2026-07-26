//! The one-round issuing protocol.
//! Report: "Issuing protocol".

use crate::keys::{PublicKey, SecretKey};
use crate::util::norm_eucl_sqrd;
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::integer_mod_q::MatPolynomialRingZq;
use qfall_tools::primitive::psf::PSF;

/// The request sent by the user. The proof pi_com is added in stage 3.
pub struct Request {
    pub commitment: MatPolynomialRingZq,
}

/// What the user keeps between the two messages.
pub struct UserState {
    pub message: MatPolyOverZ,
    pub randomness: MatPolyOverZ,
    pub commitment: MatPolynomialRingZq,
}

/// The response sent by the signer.
pub struct Response {
    pub function_input: Z,
    pub function_randomness: Z,
    pub preimage: MatPolyOverZ,
}

/// Step 1: the user samples r, commits, and keeps its state.
pub fn user_request(public_key: &PublicKey, message: &MatPolyOverZ) -> (Request, UserState) {
    let degree = public_key.function.modulus().get_degree();
    assert!(
        norm_eucl_sqrd(message, degree) <= public_key.message_bound_sqrd,
        "the message is outside the message space",
    );
    let randomness = public_key.commitment_key.sample_randomness();
    let commitment = public_key.commitment_key.commit(message, &randomness);
    let state = UserState {
        message: message.clone(),
        randomness,
        commitment: commitment.clone(),
    };
    (Request { commitment }, state)
}

/// Step 2: the signer samples mu and xi, then a short preimage for
/// the target f(kappa, mu, xi) + c. It returns None when the preimage
/// misses the norm bound.
pub fn signer_respond(
    public_key: &PublicKey,
    secret_key: &SecretKey,
    request: &Request,
) -> Option<Response> {
    let function_input = public_key.function.sample_input();
    let function_randomness = public_key.function.sample_randomness();
    let target = &public_key.function.eval(
        &public_key.function_key,
        &function_input,
        &function_randomness,
    ) + &request.commitment;
    let preimage = public_key
        .psf
        .samp_p(&public_key.a, &secret_key.trapdoor, &target);
    if !public_key.psf.check_domain(&preimage) {
        return None;
    }
    Some(Response {
        function_input,
        function_randomness,
        preimage,
    })
}

/// Step 3: the user checks the response.
pub fn user_check(public_key: &PublicKey, state: &UserState, response: &Response) -> bool {
    // The norm bound comes first because the reused f_a asserts it.
    public_key
        .function
        .contains_input(&response.function_input)
        && public_key
            .function
            .contains_randomness(&response.function_randomness)
        && public_key.psf.check_domain(&response.preimage)
        && public_key.psf.f_a(&public_key.a, &response.preimage)
            == &public_key.function.eval(
                &public_key.function_key,
                &response.function_input,
                &response.function_randomness,
            ) + &state.commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{
        key_gen,
        tests::{toy_function, toy_parameters, toy_psf},
    };

    const D: i64 = 8;

    fn setup() -> (PublicKey, SecretKey, MatPolyOverZ) {
        let psf = toy_psf();
        let function = toy_function(&psf, "issue-test");
        let (public_key, secret_key) = key_gen(function, psf, toy_parameters());
        let message = MatPolyOverZ::sample_uniform(2, 1, D - 1, 0, 2).unwrap();
        (public_key, secret_key, message)
    }

    #[test]
    fn honest_run_passes_the_user_check() {
        let (public_key, secret_key, message) = setup();
        let (request, state) = user_request(&public_key, &message);
        let response = signer_respond(&public_key, &secret_key, &request).expect("signer aborted");
        assert!(user_check(&public_key, &state, &response));
    }

    /// After an honest run the user holds a witness for the final
    /// relation A s = f(kappa, mu, xi) + B_1 m + B_2 r.
    #[test]
    fn finalisation_identity_holds() {
        let (public_key, secret_key, message) = setup();
        let (request, state) = user_request(&public_key, &message);
        let response = signer_respond(&public_key, &secret_key, &request).expect("signer aborted");
        let left = public_key.psf.f_a(&public_key.a, &response.preimage);
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
        let (request, state) = user_request(&public_key, &message);
        let mut response =
            signer_respond(&public_key, &secret_key, &request).expect("signer aborted");
        response.function_input = &response.function_input + &Z::ONE;
        assert!(!user_check(&public_key, &state, &response));
    }

    #[test]
    fn changed_function_randomness_fails_the_user_check() {
        let (public_key, secret_key, message) = setup();
        let (request, state) = user_request(&public_key, &message);
        let mut response =
            signer_respond(&public_key, &secret_key, &request).expect("signer aborted");
        response.function_randomness = &response.function_randomness + &Z::ONE;
        assert!(!user_check(&public_key, &state, &response));
    }

    #[test]
    fn changed_preimage_fails_the_user_check() {
        let (public_key, secret_key, message) = setup();
        let (request, state) = user_request(&public_key, &message);
        let mut response =
            signer_respond(&public_key, &secret_key, &request).expect("signer aborted");
        response.preimage = &response.preimage + &response.preimage;
        assert!(!user_check(&public_key, &state, &response));
    }

    #[test]
    #[should_panic(expected = "outside the message space")]
    fn oversized_message_is_rejected() {
        let (public_key, _, _) = setup();
        let big = MatPolyOverZ::sample_uniform(2, 1, D - 1, 100, 200).unwrap();
        user_request(&public_key, &big);
    }
}
