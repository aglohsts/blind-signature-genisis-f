//! An interactive run of the scheme. Type a message, watch the four
//! protocol steps, and see the signature checked.
//! Report: "Prototype Implementation".
//!
//! The parameters are the toy ones, so this is quick enough to be
//! interactive but gives no security. The LaZer proof layer is not used
//! here; the commitment proof is the native Fiat--Shamir one and the
//! signature is transparent, which is what lets the demo run on any
//! platform. `tests/lazer_protocol.rs` exercises the proof layer.
//!
//! Messages given on the command line are signed in order and the
//! program exits; with no arguments it reads them from the terminal.

use blind_sig::commitment_proof::FiatShamirProvider;
use blind_sig::hash_to_ring::HashToRing;
use blind_sig::issue::{signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, PublicKey, SecretKey, key_gen};
use blind_sig::preimage::{Sampler, gadget_parameters};
use blind_sig::proof_com::ProofParameters;
use blind_sig::signature::{finalise, verify};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{MatrixGetEntry, MatrixSetEntry, SetCoefficient};
use qfall_schemes::hash::sha256::hash_to_mat_zq_sha256;
use std::io::{self, BufRead, Write};
use std::time::Instant;

const D: i64 = 8;
const Q_MOD: u64 = 257;
const ELL_M: i64 = 2;

/// The message space holds `ELL_M * D` coefficients and the norm bound
/// is 16, so a binary vector of that length always fits. That is two
/// bytes, which is why real input is hashed down to it first: the
/// message space of these toy parameters is smaller than any message
/// worth signing.
const MESSAGE_BITS: i64 = ELL_M * D;

/// Hashes text into the message space. Every coefficient is 0 or 1, so
/// the squared norm is the number of ones and never exceeds the bound.
fn encode(text: &str) -> (MatPolyOverZ, String) {
    let bits = hash_to_mat_zq_sha256(text, MESSAGE_BITS, 1, 2)
        .get_representative_least_nonnegative_residue();

    let mut message = MatPolyOverZ::new(ELL_M, 1);
    let mut shown = String::new();
    for row in 0..ELL_M {
        let mut polynomial = PolyOverZ::default();
        for index in 0..D {
            let bit: Z = bits.get_entry(row * D + index, 0).unwrap();
            let bit = i64::try_from(&bit).unwrap();
            polynomial.set_coeff(index, bit).unwrap();
            shown.push(if bit == 1 { '1' } else { '0' });
        }
        message.set_entry(row, 0, &polynomial).unwrap();
    }
    (message, shown)
}

/// Runs the four steps of the protocol on one message and reports each.
fn sign_and_report(
    public_key: &PublicKey<HashToRing>,
    secret_key: &SecretKey,
    text: &str,
) {
    let (message, bits) = encode(text);
    println!("  hashed into the message space : {bits}");

    let started = Instant::now();
    let (request, state) = match user_request(public_key, &message, &FiatShamirProvider) {
        Ok(pair) => pair,
        Err(_) => unreachable!("the Fiat-Shamir prover cannot fail"),
    };
    println!(
        "  1  user   -> signer  commitment and pi_com    {:>8.2} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );

    let started = Instant::now();
    let Some(response) = signer_respond(public_key, secret_key, &request, &FiatShamirProvider)
    else {
        println!("  2  the signer aborted: the proof or the preimage bound failed");
        return;
    };
    println!(
        "  2  signer -> user    mu, xi and a preimage    {:>8.2} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    println!("       mu = {}, xi = {}", response.function_input, response.function_randomness);

    let started = Instant::now();
    let accepted = user_check(public_key, &state, &response);
    println!(
        "  3  user checks the response          {:>16}",
        if accepted { "ok" } else { "REJECTED" }
    );
    println!("       took {:.2} ms", started.elapsed().as_secs_f64() * 1000.0);
    if !accepted {
        return;
    }

    let signature = finalise(state, response);
    let started = Instant::now();
    let valid = verify(public_key, &message, &signature);
    println!(
        "  4  verify the signature              {:>16}",
        if valid { "ACCEPT" } else { "REJECT" }
    );
    println!("       took {:.2} ms", started.elapsed().as_secs_f64() * 1000.0);

    // The same signature against a different message must fail. This is
    // the check that makes the signature about this message and not
    // just well-formed.
    let (other, _) = encode(&format!("{text} "));
    println!(
        "     the same signature for \"{text} \"    {:>16}",
        if verify(public_key, &other, &signature) {
            "ACCEPT (wrong!)"
        } else {
            "REJECT (correct)"
        }
    );
}

fn main() {
    println!("== blind-sig, interactive ==");
    println!("ring R_q = Z_{Q_MOD}[X]/(X^{D} + 1), module rank 1, message space {MESSAGE_BITS} bits");
    println!("toy parameters: quick enough to be interactive, and not secure");
    println!("the commitment proof is the native one; the signature carries its witness\n");

    let sampler = Sampler::new(
        gadget_parameters(D, Q_MOD, 1),
        Q::from(100),
        Q::from(1.005_f64),
    );
    let function = HashToRing::new(
        1,
        1u64 << 10,
        1u64 << 20,
        1u64 << 10,
        sampler.modulus().clone(),
        "demo",
    );
    let parameters = Parameters {
        ell_m: ELL_M,
        ell_r: 2,
        psi: 3,
        message_bound_sqrd: Z::from(16),
        proof: ProofParameters {
            witness_inf: 20,
            mask_inf: 8000,
        },
    };

    let started = Instant::now();
    let (public_key, secret_key) = key_gen(function, sampler, parameters);
    println!(
        "key generation                         {:>8.2} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    println!("the function key kappa = {}\n", public_key.function_key);

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if !arguments.is_empty() {
        for text in &arguments {
            println!("message: {text}");
            sign_and_report(&public_key, &secret_key, text);
            println!();
        }
        return;
    }

    println!("Type a message and press enter. An empty line quits.");
    println!("Signing the same message twice shows a different transcript,");
    println!("which is the freshness that blindness rests on.\n");

    let stdin = io::stdin();
    loop {
        print!("message> ");
        io::stdout().flush().ok();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                eprintln!("could not read input: {error}");
                break;
            }
        }
        let text = line.trim_end_matches(['\n', '\r']);
        if text.is_empty() {
            break;
        }
        sign_and_report(&public_key, &secret_key, text);
        println!();
    }
    println!("done");
}
