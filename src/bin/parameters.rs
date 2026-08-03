// report: "Making the Two Components Meet"
//
// usage: cargo run --release --bin parameters [degree] [modulus] [base]

use blind_sig::preimage::{Sampler, gadget_parameters};
use qfall_math::rational::Q;
use qfall_math::traits::MatrixDimensions;
use std::time::Instant;

// LaZer applies to a witness norm before squaring it for its modulus condition
// read from its generator
const RANGE_PROOF_SLACK: f64 = 3358.0;

// The degree the proof profile runs at.
const TARGET_DEGREE: f64 = 64.0;

const BASES: [u32; 7] = [2, 4, 16, 64, 256, 4096, 65536];

fn legend() {
    println!("Columns:");
    println!("  base        gadget base b, the trapdoor needs one column per digit");
    println!("              of q written in base b");
    println!("  m           columns of A, which is ceil(log_b q) + 2");
    println!("  min width   smallest Gaussian width the sampler may use with a basis");
    println!("              this coarse, from the GPV smoothing condition at 2^-64");
    println!("  |s| bound   norm bound on the preimage that this width gives at d = 64");
    println!("  log2 q      modulus the proof system needs to prove that bound");
    println!("  trap gen    time to build the trapdoor and orthogonalise its basis");
    println!();
    println!("A larger base makes m smaller, which is what makes the orthogonalisation");
    println!("affordable, but it also makes the basis coarser and so needs a wider");
    println!("Gaussian. A wider Gaussian raises the norm bound, and a higher bound");
    println!("raises the modulus the proof system needs. The three columns on the");
    println!("right are that chain.");
    println!();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("-h") || first.as_deref() == Some("--help") {
        println!("usage: parameters [degree] [modulus] [base]");
        println!("       base must be a power of two, omit it to try every base");
        println!();
        legend();
        return;
    }

    let degree: i64 = first.and_then(|v| v.parse().ok()).unwrap_or(8);
    let modulus: u64 = args
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(288_230_376_151_713_349);
    let chosen: Option<u32> = args.next().and_then(|v| v.parse().ok());

    let bases: Vec<u32> = match chosen {
        Some(base) => {
            if !base.is_power_of_two() || base < 2 {
                eprintln!("parameters: the base must be a power of two, at least 2");
                std::process::exit(2);
            }
            vec![base]
        }
        None => BASES.to_vec(),
    };

    println!("Preimage sampler parameters at d = {degree}, q = {modulus}");
    println!();
    legend();

    if degree < TARGET_DEGREE as i64 {
        println!("Warning: this run is at d = {degree}, but the proof system runs at");
        println!("d = {}. Gram-Schmidt norms grow with the degree, so the", TARGET_DEGREE as i64);
        println!("widths below are too small. Pick a base here, then run again at");
        println!("d = {} with that base to read the width you can use.", TARGET_DEGREE as i64);
        println!();
    }

    println!(
        "{:>7} {:>4} {:>11} {:>14} {:>8} {:>10}",
        "base", "m", "min width", "|s| bound", "log2 q", "trap gen"
    );

    for base in bases {
        let log_base = base.trailing_zeros();
        let sampler = Sampler::new(
            gadget_parameters(degree, modulus, log_base),
            Q::from(1),
            Q::from(1.005_f64),
        );
        let started = Instant::now();
        let (a, trapdoor) = sampler.trap_gen();
        let trap_gen = started.elapsed().as_secs_f64();
        let columns = a.get_num_columns();
        let width = sampler.least_width(&trapdoor);

        // stated at the degree the proof system runs at, not at the degree this sweep happens to use
        let bound_sqrd = width * width * columns as f64 * TARGET_DEGREE;
        let slack_bound = RANGE_PROOF_SLACK * bound_sqrd.sqrt();
        println!(
            "{base:>7} {columns:>4} {width:>11.1} {bound_sqrd:>14.3e} {:>8.1} {trap_gen:>8.1} s",
            (slack_bound * slack_bound).log2()
        );
    }
}
