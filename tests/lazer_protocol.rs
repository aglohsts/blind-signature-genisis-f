#![cfg(feature = "lazer-ffi")]

//! LaZer commitment proof in the full issuing protocol.
//! Report: "LaZer Integration Validation".

use blind_sig::commitment::CommitmentKey;
use blind_sig::commitment_proof::{
    CommitmentProofProvider, LazerD64CommitmentProof, LazerD64CommitmentProofProvider,
};
use blind_sig::issue::{
    IssueError, PreimageSampler, SignerResponse, TagSampler, UserCommitMessage, UserState,
    signer_respond_with_components, signer_respond_with_provider, user_check,
    user_commit_with_provider, verify_user_commit_with_provider,
};
use blind_sig::keys::{KeyGenParams, PublicKey, SecretKey, key_gen};
use blind_sig::lazer_ffi::Error;
use blind_sig::proof_com::ComProofParams;
use blind_sig::signature::{
    LazerD64FinalSignatureProofProvider, finalize, finalize_with_provider, verify,
    verify_with_provider,
};
use blind_sig::tag_function::{BinaryEncoding, HashToRing, TagFunction};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::integer_mod_q::{MatPolynomialRingZq, ModulusPolynomialRingZq};
use qfall_math::rational::Q;
use qfall_math::traits::{MatrixSetEntry, SetCoefficient};
use qfall_tools::primitive::psf::{PSF, PSFGPVRing};
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;
use std::cell::RefCell;

const D: i64 = 64;
const Q_MOD: u64 = 281_474_976_711_349;

struct FixedTagFunction {
    modulus: ModulusPolynomialRingZq,
    output: RefCell<MatPolynomialRingZq>,
}

struct FixedTagSampler {
    x: Z,
}

impl TagSampler for FixedTagSampler {
    fn sample_tag(&self, _domain_size: &Z) -> Result<Z, IssueError> {
        Ok(self.x.clone())
    }
}

struct FixturePreimageSampler {
    s: MatPolyOverZ,
}

impl PreimageSampler for FixturePreimageSampler {
    fn sample<F: TagFunction>(
        &self,
        _pk: &PublicKey<F>,
        _sk: &SecretKey,
        _target: &MatPolynomialRingZq,
    ) -> Result<MatPolyOverZ, IssueError> {
        Ok(self.s.clone())
    }
}

impl FixedTagFunction {
    fn new(modulus: ModulusPolynomialRingZq) -> Self {
        let zero = MatPolynomialRingZq::from((&MatPolyOverZ::new(1, 1), &modulus));
        Self {
            modulus,
            output: RefCell::new(zero),
        }
    }

    fn set_output(&self, output: MatPolynomialRingZq) {
        *self.output.borrow_mut() = output;
    }
}

impl TagFunction for FixedTagFunction {
    fn domain_size(&self) -> Z {
        Z::ONE
    }

    fn rows(&self) -> i64 {
        1
    }

    fn modulus(&self) -> &ModulusPolynomialRingZq {
        &self.modulus
    }

    fn eval(&self, x: &Z) -> MatPolynomialRingZq {
        assert_eq!(&Z::ONE, x);
        self.output.borrow().clone()
    }
}

fn psf(degree: i64) -> PSFGPVRing {
    PSFGPVRing {
        gp: GadgetParametersRing::init_default(degree, Q_MOD),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    }
}

fn params() -> KeyGenParams {
    KeyGenParams {
        ell_m: 2,
        ell_r: 2,
        s_r: Q::from(3),
        beta_msg_sqrd: Z::from(16),
        beta_r_sqrd: Z::from(2000),
        com_params: ComProofParams {
            witness_inf: 20,
            mask_inf: 8000,
        },
    }
}

fn standard_keys() -> (PublicKey<HashToRing>, SecretKey) {
    let psf = psf(8);
    let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "lazer-protocol");
    key_gen(f, psf, params())
}

fn d64_keys() -> (PublicKey<FixedTagFunction>, SecretKey) {
    let psf = psf(D);
    let modulus = psf.gp.modulus.clone();
    let (a, trapdoor) = psf.trap_gen();
    (
        PublicKey {
            a,
            ck: CommitmentKey::generate(2, 2, &modulus),
            f: FixedTagFunction::new(modulus),
            psf,
            s_r: Q::from(3),
            beta_msg_sqrd: Z::from(16),
            beta_r_sqrd: Z::from(2000),
            com_params: ComProofParams {
                witness_inf: 20,
                mask_inf: 8000,
            },
        },
        SecretKey { trapdoor },
    )
}

fn d64_binary_fixture() -> (
    PublicKey<BinaryEncoding>,
    SecretKey,
    MatPolyOverZ,
    MatPolyOverZ,
    MatPolyOverZ,
) {
    let psf = psf(D);
    let modulus = psf.gp.modulus.clone();
    let mut a = MatPolyOverZ::new(1, 51);
    let mut x = PolyOverZ::default();
    x.set_coeff(1, 1).unwrap();
    a.set_entry(0, 0, x).unwrap();

    let mut b1 = MatPolyOverZ::new(1, 2);
    b1.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
    let mut b2 = MatPolyOverZ::new(1, 2);
    b2.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
    let pk = PublicKey {
        a: MatPolynomialRingZq::from((&a, &modulus)),
        ck: CommitmentKey {
            b1: MatPolynomialRingZq::from((&b1, &modulus)),
            b2: MatPolynomialRingZq::from((&b2, &modulus)),
        },
        f: BinaryEncoding::new(1, D, modulus),
        psf,
        s_r: Q::from(3),
        beta_msg_sqrd: Z::from(16),
        beta_r_sqrd: Z::from(2000),
        com_params: ComProofParams {
            witness_inf: 20,
            mask_inf: 8000,
        },
    };
    let sk = SecretKey {
        trapdoor: (MatPolyOverZ::new(1, 1), MatPolyOverZ::new(1, 1)),
    };

    let mut message = MatPolyOverZ::new(2, 1);
    message.set_entry(0, 0, PolyOverZ::from(-3)).unwrap();
    let mut randomness = MatPolyOverZ::new(2, 1);
    randomness.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
    let mut preimage = MatPolyOverZ::new(51, 1);
    let mut last = PolyOverZ::default();
    last.set_coeff(D - 1, 2).unwrap();
    preimage.set_entry(0, 0, last).unwrap();
    (pk, sk, message, randomness, preimage)
}

fn sparse_message() -> MatPolyOverZ {
    let mut message = MatPolyOverZ::new(2, 1);
    message.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
    message
}

#[test]
fn lazer_commitment_proof_runs_in_the_issuing_protocol() {
    let (mut pk, sk) = d64_keys();
    let message = sparse_message();
    let provider = LazerD64CommitmentProofProvider::new([7; 32]);
    let (first_message, state) =
        user_commit_with_provider(&pk, &message, &provider).expect("LaZer proof");

    assert!(verify_user_commit_with_provider(
        &pk,
        &first_message,
        &provider
    ));

    let wrong_seed = LazerD64CommitmentProofProvider::new([8; 32]);
    assert!(signer_respond_with_provider(&pk, &sk, &first_message, &wrong_seed).is_err());

    let mut altered_bytes = first_message.proof.as_bytes().to_vec();
    altered_bytes[0] ^= 1;
    let altered_proof = UserCommitMessage {
        c: first_message.c.clone(),
        proof: LazerD64CommitmentProof::from_bytes(altered_bytes),
    };
    assert!(signer_respond_with_provider(&pk, &sk, &altered_proof, &provider).is_err());

    let mut shift = MatPolyOverZ::new(1, 1);
    shift.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
    let shift = MatPolynomialRingZq::from((&shift, pk.f.modulus()));
    let altered_statement = UserCommitMessage {
        c: &first_message.c + &shift,
        proof: first_message.proof.clone(),
    };
    assert!(signer_respond_with_provider(&pk, &sk, &altered_statement, &provider).is_err());

    let s = pk.psf.samp_d();
    let target = pk.psf.f_a(&pk.a, &s);
    pk.f.set_output(&target - &state.c);
    let response = SignerResponse { x: Z::ONE, s };
    assert!(user_check(&pk, &state, &response));
    let signature = finalize(state, response);
    assert!(verify(&pk, &message, &signature));

    let mut high_degree_message = sparse_message();
    let mut high_degree_entry = PolyOverZ::default();
    high_degree_entry.set_coeff(D, 1).unwrap();
    high_degree_message
        .set_entry(0, 0, high_degree_entry)
        .unwrap();
    let zero_randomness = MatPolyOverZ::new(2, 1);
    let commitment = pk.ck.commit(&high_degree_message, &zero_randomness);
    assert!(matches!(
        provider.prove(&pk, &high_degree_message, &zero_randomness, &commitment),
        Err(Error::ProfileMismatch(_))
    ));

    pk.beta_r_sqrd = Z::from(2001);
    assert!(matches!(
        user_commit_with_provider(&pk, &message, &provider),
        Err(Error::ProfileMismatch(_))
    ));
}

#[test]
fn lazer_provider_rejects_the_standard_d8_profile() {
    let (pk, _) = standard_keys();
    let result = user_commit_with_provider(
        &pk,
        &sparse_message(),
        &LazerD64CommitmentProofProvider::new([7; 32]),
    );
    assert!(matches!(result, Err(Error::ProfileMismatch(_))));
}

#[test]
fn advanced_fixture_runs_both_lazer_proofs() {
    let (pk, sk, message, randomness, preimage) = d64_binary_fixture();
    let commitment = pk.ck.commit(&message, &randomness);
    let commitment_provider = LazerD64CommitmentProofProvider::new([7; 32]);
    let commitment_proof = commitment_provider
        .prove(&pk, &message, &randomness, &commitment)
        .expect("commitment proof");
    let first_message = UserCommitMessage {
        c: commitment.clone(),
        proof: commitment_proof,
    };
    let state = UserState {
        m: message.clone(),
        r: randomness,
        c: commitment,
    };

    let response = signer_respond_with_components(
        &pk,
        &sk,
        &first_message,
        &commitment_provider,
        &FixedTagSampler { x: Z::ONE },
        &FixturePreimageSampler { s: preimage },
    )
    .expect("fixture response");
    assert!(user_check(&pk, &state, &response));

    let signature_provider = LazerD64FinalSignatureProofProvider::new([8; 32]);
    let signature = finalize_with_provider(&pk, state, response, &signature_provider)
        .expect("final-signature proof");
    assert!(verify_with_provider(
        &pk,
        &message,
        &signature,
        &signature_provider
    ));
}
