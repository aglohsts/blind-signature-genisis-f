// report: "Testing", the demo binary
// An interactive run of the scheme. Type a message, watch the four
// protocol steps, and see the signature checked.
//
// The parameters are the toy ones, so this is quick enough to be
// interactive but gives no security. The LaZer proof layer is not used
// here; the commitment proof is the native Fiat--Shamir one and the
// signature is transparent, which is what lets the demo run on any
// platform. `tests/lazer_protocol.rs` exercises the proof layer.
//
// Messages given on the command line are signed in order and the
// program exits; with no arguments it reads them from the terminal.
//
// `--sampler=stored` or `--sampler=per-call` chooses which preimage
// sampler the key uses. The two are interchangeable and produce
// signatures the same verifier accepts; they differ in when the short
// basis is orthogonalised, which is what the timings below make
// visible.

use blind_sig::commitment_proof::FiatShamirProvider;
use blind_sig::hash_to_ring::HashToRing;
use blind_sig::issue::{signer_respond, user_check, user_request};
use blind_sig::keys::{Parameters, PublicKey, SecretKey, key_gen};
use blind_sig::preimage::{Sampler, Sampling, gadget_parameters};
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

// message space holds `ELL_M * D` coefficients and the norm bound is 16, so a binary vector of that length always fits
// 2 bytes, which is why real input is hashed down to it first: the message space of these toy parameters is smaller than any message worth signing
const MESSAGE_BITS: i64 = ELL_M * D;

// every coefficient is 0 or 1, so the squared norm is the number of ones and never exceeds the bound
fn encode(text: &str) -> (MatPolyOverZ, String) { // hash text into the message space
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

fn sign_and_report(
    public_key: &PublicKey<HashToRing>,
    secret_key: &SecretKey,
    text: &str,
) { // run the four steps of the protocol on one message and report each
    let (message, bits) = encode(text);
    println!("  message as bits          {bits}");

    let started = Instant::now();
    let (request, state) = match user_request(public_key, &message, &FiatShamirProvider) {
        Ok(pair) => pair,
        Err(_) => unreachable!("the Fiat-Shamir prover cannot fail"),
    };
    println!(
        "  Step 1  user -> signer   sends c and the proof      {:>8.2} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );

    let started = Instant::now();
    let response = match signer_respond(public_key, secret_key, &request, &FiatShamirProvider) {
        Ok(response) => response,
        Err(reason) => {
            println!("  Step 2  the signer refused to answer: {reason:?}");
            return;
        }
    };
    println!(
        "  Step 2  signer -> user   sends mu, xi and s         {:>8.2} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
    println!(
        "          mu = {}, xi = {}",
        response.function_input, response.function_randomness
    );

    let started = Instant::now();
    let accepted = user_check(public_key, &state, &response);
    println!(
        "  Step 3  user checks it   {:>26}  {:>8.2} ms",
        if accepted { "accepted" } else { "REJECTED" },
        started.elapsed().as_secs_f64() * 1000.0
    );
    if !accepted {
        return;
    }

    let signature = finalise(state, response);
    let started = Instant::now();
    let valid = verify(public_key, &message, &signature);
    println!(
        "  Step 4  anyone verifies  {:>26}  {:>8.2} ms",
        if valid { "ACCEPTED" } else { "REJECTED" },
        started.elapsed().as_secs_f64() * 1000.0
    );

    // The same signature against a different message must fail, or the
    // signature would say nothing about which message was signed.
    let (other, _) = encode(&format!("{text} "));
    println!(
        "          same signature, message \"{text} \" -> {}",
        if verify(public_key, &other, &signature) {
            "ACCEPTED (this is a bug)"
        } else {
            "rejected, as it should be"
        }
    );
}

// everything else: returned in order and treated as a message
fn parse_arguments() -> Result<(Sampling, Vec<String>), String> { // split `--sampler=<mode>` out of the arguments
    let mut sampling = Sampling::default();
    let mut messages = Vec::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = match argument.strip_prefix("--sampler=") {
            Some(value) => Some(value.to_string()),
            None if argument == "--sampler" => Some(
                arguments
                    .next()
                    .ok_or_else(|| "--sampler needs a value".to_string())?,
            ),
            None => None,
        };
        match value {
            Some(value) => {
                sampling = Sampling::parse(&value).ok_or_else(|| {
                    format!("unknown sampler \"{value}\"; use \"stored\" or \"per-call\"")
                })?;
            }
            None => messages.push(argument),
        }
    }
    Ok((sampling, messages))
}

fn main() {
    let (sampling, arguments) = match parse_arguments() {
        Ok(parsed) => parsed,
        Err(problem) => {
            eprintln!("blind-sig: {problem}");
            eprintln!("usage: blind-sig [--sampler=stored|per-call] [message ...]");
            std::process::exit(2);
        }
    };

    println!("blind-sig: a lattice-based blind signature");
    println!();
    println!("A blind signature lets a signer sign a message without seeing it.");
    println!("The signer cannot later tell which signature came from which of its");
    println!("own signing sessions. This program runs one signing session at a");
    println!("time and prints the four steps it goes through:");
    println!();
    println!("  Step 1  The user hides the message inside a commitment c, and");
    println!("          proves it knows how to open c without revealing anything.");
    println!("  Step 2  The signer checks that proof, then picks two random values");
    println!("          mu and xi and uses its secret trapdoor to find a short");
    println!("          vector s solving  A s = f(kappa, mu, xi) + c.");
    println!("          The signer never sees the message.");
    println!("  Step 3  The user checks that s really solves that equation and is");
    println!("          short enough, in case the signer cheated.");
    println!("  Step 4  The user turns what it received into a signature, and");
    println!("          anyone can verify it against the message.");
    println!();
    println!("Settings for this run:");
    println!("  ring          R_q = Z_{Q_MOD}[X]/(X^{D} + 1), module rank 1");
    println!("  message space {MESSAGE_BITS} bits, so your text is hashed down to fit");
    println!("  security      none: these are toy sizes, chosen to run fast");
    println!("  signature     carries its values in the open, so this demo gives");
    println!("                no blindness; the LaZer tests cover the hidden form");
    match sampling {
        Sampling::StoredBasis => println!(
            "  sampler       stored: the short basis is prepared once, at key setup"
        ),
        Sampling::PerCall => println!(
            "  sampler       per-call: the short basis is prepared again every time"
        ),
    }
    println!();

    let sampler = Sampler::with_sampling(
        gadget_parameters(D, Q_MOD, 1),
        Q::from(100),
        Q::from(1.005_f64),
        sampling,
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
        "Key setup (once)         {:>26}  {:>8.2} ms",
        format!("kappa = {}", public_key.function_key),
        started.elapsed().as_secs_f64() * 1000.0
    );
    println!();

    if !arguments.is_empty() {
        for text in &arguments {
            println!("message: {text}");
            sign_and_report(&public_key, &secret_key, text);
            println!();
        }
        return;
    }

    println!("Type a message and press enter. An empty line quits.");
    println!("Sign the same message twice: the values differ each time, because");
    println!("fresh randomness is used. That freshness is what blindness needs.\n");

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
