//! Calibrates the gadget base against the Gaussian width.
//! Report: "Making the Two Components Meet".
//!
//! A larger gadget base shortens the preimage, which is what makes the
//! orthogonalisation of the short basis affordable, but it also makes
//! the basis coarser. Klein's sampler is only statistically correct
//! for a width above the largest Gram-Schmidt norm of the basis times
//! a smoothing factor, so a coarser basis forces a wider Gaussian. A
//! wider Gaussian raises the norm bound the proof relation states, and
//! the proof system requires a modulus above roughly the square of
//! that bound.
//!
//! This binary reports that chain for each base, so the parameters can
//! be chosen rather than guessed. A width that merely makes the
//! sampler return is not enough: below the smoothing bound the output
//! distribution depends on the basis, which is what leaks the trapdoor.
//!
//! The width has to be read at the degree the scheme will run at. The
//! Gram-Schmidt norms of the basis grow with the ring degree, so a
//! width taken at a smaller degree is an underestimate, and an
//! underestimate is the dangerous direction. Measured at base 256, the
//! width at degree 64 is 3023 where degree 8 gives 1480. Sweeping every
//! base is only affordable at a small degree, so use the sweep to pick
//! a base and then re-run at the real degree with that base to fix the
//! width.
//!
//! Usage: cargo run --release --bin calibrate [degree] [modulus] [log2 base]
//!
//! Passing a base measures only that one, and also reports how long
//! the one-off orthogonalisation takes. Without it the sweep covers
//! every base, which is only affordable at the toy degree.

use blind_sig::preimage::{Sampler, gadget_parameters};
use qfall_math::rational::Q;
use qfall_math::traits::MatrixDimensions;
use std::time::Instant;

/// The slack the proof system applies to the witness norm before it
/// squares it for its modulus condition. Taken from LaZer's generator.
const RANGE_PROOF_SLACK: f64 = 3358.0;

/// The degree the proof profile runs at, which is where the bound and
/// the modulus condition matter.
const TARGET_DEGREE: f64 = 64.0;

fn main() {
    let mut args = std::env::args().skip(1);
    let degree: i64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(8);
    let modulus: u64 = args
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(288_230_376_151_713_349);
    let only: Option<u32> = args.next().and_then(|v| v.parse().ok());
    let bases: Vec<u32> = match only {
        Some(base) => vec![base],
        None => vec![1, 2, 4, 6, 8, 12, 16],
    };

    println!("calibrating at d = {degree}, q = {modulus}");
    println!("the last column is the modulus the proof system would need");
    if degree < TARGET_DEGREE as i64 {
        println!(
            "WARNING: run at d = {degree}, so the widths below are lower than\n\
             they are at d = {}; re-run at the real degree before using one.",
            TARGET_DEGREE as i64
        );
    }
    println!(
        "{:>6} {:>4} {:>13} {:>15} {:>13}",
        "log2 b", "m", "least width", "bound at d=64", "needs log2 q"
    );

    for log_base in bases {
        let sampler = Sampler::new(
            gadget_parameters(degree, modulus, log_base),
            Q::from(1),
            Q::from(1.005_f64),
        );
        let started = Instant::now();
        let (a, trapdoor) = sampler.trap_gen();
        let setup = started.elapsed().as_secs_f64();
        let columns = a.get_num_columns();
        let width = sampler.least_width(&trapdoor);

        // The bound is stated at the degree the proof system runs at.
        // When this sweep is run at a smaller degree the width, and so
        // the bound, is an underestimate.
        let bound_sqrd = width * width * columns as f64 * TARGET_DEGREE;
        let barp = RANGE_PROOF_SLACK * bound_sqrd.sqrt();
        println!(
            "{log_base:>6} {columns:>4} {width:>13.1} {bound_sqrd:>15.3e} {:>13.1}   setup {setup:.1} s",
            (barp * barp).log2()
        );
    }
}
