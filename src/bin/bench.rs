//! Benchmark: step timings and size estimates for both tag functions.
//! Toy parameters; run with --release. Report: "Evaluation".

use blind_sig::issue::{signer_respond, user_check, user_commit};
use blind_sig::keys::key_gen;
use blind_sig::proof_com::ComProofParams;
use blind_sig::signature::{finalize, verify};
use blind_sig::tag_function::{BinaryEncoding, HashToRing, TagFunction};
use qfall_math::integer::{MatPolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{IntoCoefficientEmbedding, MatrixDimensions};
use qfall_tools::primitive::psf::PSFGPVRing;
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;
use std::hint::black_box;
use std::time::Instant;

const D: i64 = 8;
const Q_MOD: u64 = 257;
const ELL_M: i64 = 2;
const ELL_R: i64 = 2;
const REPS: u32 = 20;

fn toy_psf() -> PSFGPVRing {
    PSFGPVRing {
        gp: GadgetParametersRing::init_default(D, Q_MOD),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    }
}

fn com_params() -> ComProofParams {
    ComProofParams {
        witness_inf: 20,
        mask_inf: 8000,
    }
}

fn time_ms<T>(reps: u32, mut f: impl FnMut() -> T) -> f64 {
    let start = Instant::now();
    for _ in 0..reps {
        black_box(f());
    }
    start.elapsed().as_secs_f64() * 1000.0 / reps as f64
}

fn max_abs_coeff(v: &MatPolyOverZ) -> Z {
    v.clone().into_coefficient_embedding(D).norm_l_infty_infty()
}

fn bits_for_signed(max_abs: &Z) -> u32 {
    let m = i64::try_from(max_abs).unwrap().unsigned_abs();
    64 - (2 * m + 1).leading_zeros()
}

fn packed_bytes(coeffs: i64, bits: u32) -> i64 {
    (coeffs * bits as i64 + 7) / 8
}

fn bench<F: TagFunction>(label: &str, f: F) {
    println!("--- {label} ---");
    let (pk, sk) = key_gen(
        f,
        toy_psf(),
        ELL_M,
        ELL_R,
        Q::from(3),
        Z::from(16),
        Z::from(2000),
        com_params(),
    );
    let m = MatPolyOverZ::sample_uniform(ELL_M, 1, D - 1, 0, 2).unwrap();

    let x_probe = Z::from(3);
    let t_eval = time_ms(1000, || pk.f.eval(&x_probe));
    let t_commit = time_ms(REPS, || user_commit(&pk, &m));
    let (msg, st) = user_commit(&pk, &m);
    let t_respond = time_ms(REPS, || signer_respond(&pk, &sk, &msg).unwrap());
    let resp = signer_respond(&pk, &sk, &msg).unwrap();
    let t_check = time_ms(REPS, || user_check(&pk, &st, &resp));
    let (st2, resp2) = (user_commit(&pk, &m).1, signer_respond(&pk, &sk, &msg).unwrap());
    let sig = finalize(st2, resp2);
    let t_verify = time_ms(REPS, || verify(&pk, &m, &sig));

    println!("timings (mean, ms):");
    println!("  f eval (1000 runs)  : {t_eval:8.4}");
    println!("  user commit + prove : {t_commit:8.2}");
    println!("  signer respond      : {t_respond:8.2}");
    println!("  user check          : {t_check:8.2}");
    println!("  verify              : {t_verify:8.2}");

    let q_bits = 9;
    let z_bits = bits_for_signed(&Z::from(pk.com_params.response_inf(D)));
    let s_bits = bits_for_signed(&max_abs_coeff(&sig.s));
    let r_bits = bits_for_signed(&max_abs_coeff(&sig.r));
    let n_bits = 64 - (u64::try_from(&pk.f.domain_size()).unwrap()).leading_zeros();
    let m_cols = pk.a.get_num_columns();

    let c_bytes = packed_bytes(D, q_bits);
    let proof_bytes =
        packed_bytes(D, 2) + packed_bytes((ELL_M + ELL_R) * D, z_bits);
    let resp_bytes = packed_bytes(m_cols * D, s_bits) + (n_bits as i64 + 7) / 8;
    let sig_bytes = packed_bytes(m_cols * D, s_bits)
        + packed_bytes(ELL_R * D, r_bits)
        + (n_bits as i64 + 7) / 8;

    println!("size estimates (packed coefficients, bytes):");
    println!("  message 1 (c + pi_com) : {}", c_bytes + proof_bytes);
    println!("  message 2 (x, s)       : {resp_bytes}");
    println!("  signature (x, s, r)    : {sig_bytes}\n");
}

fn main() {
    println!("== blind-sig benchmark (toy parameters, d = {D}, q = {Q_MOD}) ==");
    println!("KeyGen mean over {REPS} runs, ms:");
    let t_keygen = time_ms(REPS, || {
        let psf = toy_psf();
        let f = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "bench");
        key_gen(
            f,
            psf,
            ELL_M,
            ELL_R,
            Q::from(3),
            Z::from(16),
            Z::from(2000),
            com_params(),
        )
    });
    println!("  key generation      : {t_keygen:8.2}\n");

    let psf = toy_psf();
    let f_hash = HashToRing::new(1, 1u64 << 20, psf.gp.modulus.clone(), "bench");
    bench("HashToRing, N = 2^20", f_hash);

    let psf = toy_psf();
    let f_bin = BinaryEncoding::new(1, 10, psf.gp.modulus.clone());
    bench("BinaryEncoding, N = 2^10", f_bin);
}
