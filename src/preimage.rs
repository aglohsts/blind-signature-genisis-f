//! Preimage sampling with a stored orthogonalised basis.
//! Report: "Making the Two Components Meet".
//!
//! The reused ring sampler rebuilds the short basis of the trapdoor on
//! every call and orthogonalises it again. Building the basis is
//! almost free; the orthogonalisation is the whole cost, and it grows
//! with the ring degree until it is out of reach at the degree the
//! proof system needs. The same library's non-ring sampler already
//! stores the orthogonalised basis in the trapdoor, so this module
//! does the same for the ring setting: the work that does not depend
//! on the target is done once, at key generation.
//!
//! Nothing else changes. The trapdoor is still the gadget trapdoor of
//! Micciancio and Peikert, `A` is still uniform, and the samples are
//! still checked against the norm bound of the reused component.

use crate::util::norm_eucl_sqrd;
use qfall_math::integer::{MatPolyOverZ, MatZ, Z};
use qfall_math::integer_mod_q::{
    MatPolynomialRingZq, MatZq, Modulus, ModulusPolynomialRingZq,
};
use qfall_math::rational::{MatQ, Q};
use qfall_math::traits::{
    FromCoefficientEmbedding, IntoCoefficientEmbedding, MatrixDimensions, MatrixGetEntry, Pow,
};
use qfall_tools::primitive::psf::{PSF, PSFGPVRing};
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;
use qfall_tools::sample::g_trapdoor::short_basis_ring::gen_short_basis_for_trapdoor_ring;
use qfall_tools::utils::rotation_matrix::rot_minus_matrix;

/// Builds gadget parameters for a chosen base.
///
/// The default of the reused component is base 2, which makes the
/// trapdoor one column per bit of the modulus. A larger base trades
/// those columns for a coarser gadget: `m` falls to
/// `log_base(q) + 2`, which is what brings the orthogonalisation
/// within reach, and the Gaussian width has to grow to match.
pub fn gadget_parameters(degree: i64, modulus: u64, log_base: u32) -> GadgetParametersRing {
    assert!(log_base >= 1, "the gadget base must be at least 2");
    let mut parameters = GadgetParametersRing::init_default(degree, modulus);
    if log_base > 1 {
        let base = Z::from(2).pow(log_base as i64).unwrap();
        let k = Z::from(&Modulus::from(modulus)).log_ceil(&base).unwrap();
        parameters.base = base;
        parameters.m_bar = k.clone() + Z::from(2);
        parameters.k = k;
    }
    parameters
}

/// Which of the two preimage samplers a key uses.
///
/// The two are interchangeable: they sample from the same distribution
/// over the same coset, and every test that holds for one holds for the
/// other. What differs is when the orthogonalisation is done, and that
/// is the whole of the difference the report measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sampling {
    /// Reuse the orthogonalisation stored in the trapdoor. Each
    /// preimage then costs a solve and a Klein sample. This is what
    /// brings degree 64 within reach and is the default.
    #[default]
    StoredBasis,
    /// Rebuild the short basis and orthogonalise it again on every
    /// call, which is what the reused component does as it is shipped.
    /// Kept so that the two can be compared in one execution and so
    /// that the cost the report measures can be reproduced.
    PerCall,
}

impl Sampling {
    /// The two modes, in a fixed order, so that tests and the benchmark
    /// cover both without repeating the list.
    pub const ALL: [Sampling; 2] = [Sampling::StoredBasis, Sampling::PerCall];

    /// The name accepted on the command line and printed in reports.
    pub fn name(self) -> &'static str {
        match self {
            Sampling::StoredBasis => "stored",
            Sampling::PerCall => "per-call",
        }
    }

    /// Parses a command-line value. Returns `None` for anything else,
    /// so the caller can report the accepted values itself.
    pub fn parse(value: &str) -> Option<Sampling> {
        match value {
            "stored" | "stored-basis" | "fast" => Some(Sampling::StoredBasis),
            "per-call" | "percall" | "reused" => Some(Sampling::PerCall),
            _ => None,
        }
    }
}

impl std::fmt::Display for Sampling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A trapdoor together with everything derived from it that does not
/// depend on the target.
///
/// The derived values are held whichever mode the sampler is in, for
/// one reason: `key_gen` checks the smoothing condition against the
/// orthogonalised basis, and that check must not be skipped because a
/// mode happens not to need the basis afterwards. The per-call mode
/// therefore also pays one orthogonalisation at key generation, and
/// then pays another on every call. What the two modes differ in is the
/// per-session cost, which is where the difference lies.
pub struct Trapdoor {
    pub r: MatPolyOverZ,
    pub e: MatPolyOverZ,
    a: MatPolynomialRingZq,
    basis: MatZ,
    basis_gso: MatQ,
    rotated_a: MatZq,
}

impl Trapdoor {
    /// The public matrix this trapdoor belongs to. The per-call sampler
    /// needs it, because the reused entry point takes `A` alongside the
    /// trapdoor rather than deriving it.
    pub fn public_matrix(&self) -> &MatPolynomialRingZq {
        &self.a
    }
}

/// A preimage sampler over `R_q`.
pub struct Sampler {
    psf: PSFGPVRing,
    sampling: Sampling,
}

impl Sampler {
    /// A sampler in the default mode, `Sampling::StoredBasis`.
    pub fn new(parameters: GadgetParametersRing, width: Q, trapdoor_width: Q) -> Sampler {
        Sampler::with_sampling(parameters, width, trapdoor_width, Sampling::default())
    }

    /// A sampler in a chosen mode.
    pub fn with_sampling(
        parameters: GadgetParametersRing,
        width: Q,
        trapdoor_width: Q,
        sampling: Sampling,
    ) -> Sampler {
        Sampler {
            psf: PSFGPVRing {
                gp: parameters,
                s: width,
                s_td: trapdoor_width,
            },
            sampling,
        }
    }

    /// Which sampler this key uses.
    pub fn sampling(&self) -> Sampling {
        self.sampling
    }

    pub fn modulus(&self) -> &ModulusPolynomialRingZq {
        &self.psf.gp.modulus
    }

    /// The Gaussian width used for preimages.
    pub fn width(&self) -> &Q {
        &self.psf.s
    }

    /// Samples `A` with its trapdoor, and does the target-independent
    /// work: the short basis, its orthogonalisation, and the rotation
    /// matrix that turns the ring equation into an integer one.
    pub fn trap_gen(&self) -> (MatPolynomialRingZq, Trapdoor) {
        let degree = self.psf.gp.modulus.get_degree();
        let (a, (r, e)) = self.psf.trap_gen();

        let basis = gen_short_basis_for_trapdoor_ring(&self.psf.gp, &a, &r, &e)
            .into_coefficient_embedding(degree);
        let basis_gso = MatQ::from(&basis).gso();

        let rotated_a = MatZq::from((
            &rot_minus_matrix(
                &a.get_representative_least_nonnegative_residue()
                    .into_coefficient_embedding(degree),
            ),
            &self.psf.gp.modulus.get_q(),
        ));

        (
            a.clone(),
            Trapdoor {
                r,
                e,
                a,
                basis,
                basis_gso,
                rotated_a,
            },
        )
    }

    /// Samples a short `s` with `A s = target`, through whichever of the
    /// two samplers this key was built with.
    pub fn samp_p(&self, trapdoor: &Trapdoor, target: &MatPolynomialRingZq) -> MatPolyOverZ {
        match self.sampling {
            Sampling::StoredBasis => self.samp_p_stored(trapdoor, target),
            Sampling::PerCall => self.samp_p_per_call(trapdoor, target),
        }
    }

    /// The reused sampler, unchanged: it rebuilds the short basis from
    /// the trapdoor and orthogonalises it again for this one target.
    fn samp_p_per_call(
        &self,
        trapdoor: &Trapdoor,
        target: &MatPolynomialRingZq,
    ) -> MatPolyOverZ {
        self.psf.samp_p(
            &trapdoor.a,
            &(trapdoor.r.clone(), trapdoor.e.clone()),
            target,
        )
    }

    /// The stored-basis sampler: the target-independent work was done
    /// at key generation, so only the solve and the Klein sample remain.
    fn samp_p_stored(&self, trapdoor: &Trapdoor, target: &MatPolynomialRingZq) -> MatPolyOverZ {
        let degree = self.psf.gp.modulus.get_degree();
        let embedded_target = MatZq::from((
            &target
                .get_representative_least_nonnegative_residue()
                .into_coefficient_embedding(degree),
            &self.psf.gp.modulus.get_q(),
        ));
        let solution: MatZ = trapdoor
            .rotated_a
            .solve_gaussian_elimination(&embedded_target)
            .unwrap()
            .get_representative_least_nonnegative_residue();

        // The Gaussian is centred at the negated solution, so that
        // adding the solution back gives a sample of the coset.
        let center = MatQ::from(&(-1 * &solution));
        let perturbation = MatZ::sample_d_precomputed_gso(
            &trapdoor.basis,
            &trapdoor.basis_gso,
            &center,
            &self.psf.s,
        )
        .unwrap();

        MatPolyOverZ::from_coefficient_embedding((&solution, degree - 1))
            + MatPolyOverZ::from_coefficient_embedding((&perturbation, degree - 1))
    }

    /// Reports whether the preimage respects the norm bound `B_s`.
    pub fn check_domain(&self, preimage: &MatPolyOverZ) -> bool {
        self.psf.check_domain(preimage)
    }

    /// Computes `A s`.
    pub fn f_a(&self, a: &MatPolynomialRingZq, preimage: &MatPolyOverZ) -> MatPolynomialRingZq {
        self.psf.f_a(a, preimage)
    }

    /// The squared norm bound that `check_domain` enforces, which is
    /// the bound the proof relation has to state.
    pub fn preimage_bound_sqrd(&self) -> Q {
        let degree = self.psf.gp.modulus.get_degree();
        &(&self.psf.s * &self.psf.s)
            * &(Q::from(self.columns()) * Q::from(degree))
    }

    /// The number of columns of `A`, which is `m` of the construction.
    /// The reused parameters call it `m_bar`; it is
    /// `log_base(q) + 2`.
    pub fn columns(&self) -> Z {
        self.psf.gp.m_bar.clone()
    }

    /// The largest squared Gram-Schmidt norm of the stored basis.
    /// Klein's sampler is only correct for a width above its square
    /// root times a smoothing factor, so it is what decides the width,
    /// and a coarser gadget raises it.
    pub fn max_gso_norm_sqrd(&self, trapdoor: &Trapdoor) -> Q {
        let mut largest = Q::ZERO;
        for row in 0..trapdoor.basis_gso.get_num_rows() {
            let mut squared = Q::ZERO;
            for column in 0..trapdoor.basis_gso.get_num_columns() {
                let entry: Q = trapdoor.basis_gso.get_entry(row, column).unwrap();
                squared = squared + &entry * &entry;
            }
            if squared > largest {
                largest = squared;
            }
        }
        largest
    }

    /// The least width at which Klein's sampler is statistically
    /// correct, for the stored basis. This is the smoothing condition
    /// of the GPV framework with the statistical distance fixed at
    /// `2^-64`; `max_gso_norm_sqrd` returns the squared norm, so the
    /// square root is taken here.
    pub fn least_width(&self, trapdoor: &Trapdoor) -> f64 {
        let dimension = trapdoor.basis_gso.get_num_rows() as f64;
        let epsilon = 2.0_f64.powi(-64);
        let smoothing = ((2.0 * dimension * (1.0 + 1.0 / epsilon)).ln()
            / std::f64::consts::PI)
            .sqrt();
        let squared: f64 = f64::try_from(&self.max_gso_norm_sqrd(trapdoor)).unwrap_or(f64::NAN);
        squared.sqrt() * smoothing
    }

    /// Reports whether this sampler's width satisfies the smoothing
    /// condition for the given trapdoor.
    ///
    /// Below that width the sampler still returns, every output still
    /// solves `A s = t`, and every output still passes the norm bound;
    /// what changes is that the output distribution starts to depend on
    /// the secret basis. No correctness test can see this, which is why
    /// the condition is evaluated here rather than recorded as a number
    /// in a comment. `key_gen` refuses a key that fails it.
    ///
    /// This walks the whole orthogonalised basis, so it costs a
    /// fraction of the orthogonalisation it is checking and is paid
    /// once per key.
    pub fn width_meets_smoothing(&self, trapdoor: &Trapdoor) -> bool {
        match f64::try_from(&self.psf.s) {
            Ok(width) => width >= self.least_width(trapdoor),
            Err(_) => false,
        }
    }

    /// Reports whether a sampled preimage is non-zero, which
    /// `R_sig` requires.
    pub fn is_non_zero(&self, preimage: &MatPolyOverZ) -> bool {
        let degree = self.psf.gp.modulus.get_degree();
        norm_eucl_sqrd(preimage, degree) > Z::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfall_math::traits::MatrixDimensions;

    const D: i64 = 8;
    const Q_MOD: u64 = 257;

    fn toy_sampler(log_base: u32) -> Sampler {
        toy_sampler_with(log_base, Sampling::default())
    }

    fn toy_sampler_with(log_base: u32, sampling: Sampling) -> Sampler {
        Sampler::with_sampling(
            gadget_parameters(D, Q_MOD, log_base),
            Q::from(100),
            Q::from(1.005_f64),
            sampling,
        )
    }

    /// Every claim made about the sampler is made about both modes, so
    /// the tests below iterate over `Sampling::ALL` rather than naming
    /// one. A mode that passed only because it is the default would not
    /// be an alternative to anything.
    #[test]
    fn a_sample_solves_the_equation_and_respects_the_bound() {
        for sampling in Sampling::ALL {
            let sampler = toy_sampler_with(1, sampling);
            let (a, trapdoor) = sampler.trap_gen();
            let target = MatPolynomialRingZq::sample_uniform(1, 1, sampler.modulus());

            let preimage = sampler.samp_p(&trapdoor, &target);
            assert_eq!(target, sampler.f_a(&a, &preimage), "{sampling}");
            assert!(sampler.check_domain(&preimage), "{sampling}");
            assert!(sampler.is_non_zero(&preimage), "{sampling}");
        }
    }

    /// Repeated calls under one trapdoor must keep working and must not
    /// repeat themselves. For the stored mode this also exercises the
    /// reuse of the cached orthogonalisation.
    #[test]
    fn repeated_samples_under_one_trapdoor_differ() {
        for sampling in Sampling::ALL {
            let sampler = toy_sampler_with(1, sampling);
            let (a, trapdoor) = sampler.trap_gen();
            let target = MatPolynomialRingZq::sample_uniform(1, 1, sampler.modulus());

            let first = sampler.samp_p(&trapdoor, &target);
            let second = sampler.samp_p(&trapdoor, &target);
            assert_eq!(target, sampler.f_a(&a, &first), "{sampling}");
            assert_eq!(target, sampler.f_a(&a, &second), "{sampling}");
            assert_ne!(first, second, "{sampling} must not be deterministic");
        }
    }

    /// The two names a user can give on the command line map onto the
    /// two modes, and nothing else is accepted.
    #[test]
    fn the_sampling_modes_round_trip_through_their_names() {
        for sampling in Sampling::ALL {
            assert_eq!(Some(sampling), Sampling::parse(sampling.name()));
        }
        assert_eq!(Some(Sampling::StoredBasis), Sampling::parse("fast"));
        assert_eq!(Some(Sampling::PerCall), Sampling::parse("reused"));
        assert_eq!(None, Sampling::parse("neither"));
        assert_eq!(Sampling::StoredBasis, Sampling::default());
    }

    /// A larger gadget base gives the same guarantees with fewer
    /// columns, which is the point of using one.
    #[test]
    fn a_larger_gadget_base_shortens_the_preimage() {
        let narrow = toy_sampler(1);
        let (narrow_a, _) = narrow.trap_gen();
        let wide = Sampler::new(
            gadget_parameters(D, Q_MOD, 4),
            Q::from(4000),
            Q::from(1.005_f64),
        );
        let (wide_a, trapdoor) = wide.trap_gen();
        assert!(wide_a.get_num_columns() < narrow_a.get_num_columns());

        let target = MatPolynomialRingZq::sample_uniform(1, 1, wide.modulus());
        let preimage = wide.samp_p(&trapdoor, &target);
        assert_eq!(target, wide.f_a(&wide_a, &preimage));
        assert!(wide.check_domain(&preimage));
    }

    /// The stored basis must not change what is sampled, only when the
    /// work is done. Both samplers are given the same trapdoor, so any
    /// difference is in the caching and not in the parameters.
    ///
    /// Checking the equation is not enough: a wrong centre would still
    /// solve it while shifting the distribution, which is what would
    /// leak the trapdoor. The mean squared norm is compared instead,
    /// because it moves under both a shifted centre and a wrong
    /// orthogonalisation. This compares two moments, not two
    /// distributions, so it is evidence rather than proof; what makes
    /// it strong is that both samplers reach the same library routine,
    /// and only the point at which the basis is orthogonalised differs.
    #[test]
    fn the_stored_basis_samples_the_same_distribution() {
        const ROUNDS: usize = 60;
        let stored = toy_sampler_with(1, Sampling::StoredBasis);
        let per_call = toy_sampler_with(1, Sampling::PerCall);
        let (a, trapdoor) = stored.trap_gen();
        let target = MatPolynomialRingZq::sample_uniform(1, 1, stored.modulus());

        // One trapdoor, one target, one set of parameters: the only
        // thing that differs between the two columns is the mode.
        let mut stored_total = Q::ZERO;
        let mut reference_total = Q::ZERO;
        for _ in 0..ROUNDS {
            let first = stored.samp_p(&trapdoor, &target);
            let second = per_call.samp_p(&trapdoor, &target);
            assert_eq!(target, stored.f_a(&a, &first));
            assert_eq!(target, per_call.f_a(&a, &second));
            stored_total = stored_total + Q::from(norm_eucl_sqrd(&first, D));
            reference_total = reference_total + Q::from(norm_eucl_sqrd(&second, D));
        }

        let stored_mean = f64::try_from(&stored_total).unwrap() / ROUNDS as f64;
        let reference_mean = f64::try_from(&reference_total).unwrap() / ROUNDS as f64;
        let deviation = (stored_mean - reference_mean).abs() / reference_mean;
        // The mean squared norm has a relative standard error near two
        // per cent over this many rounds, so ten is a wide margin
        // against flakiness and still far below any real discrepancy.
        assert!(
            deviation < 0.10,
            "mean squared norm differs by {:.1}%: stored {stored_mean:.0}, reused {reference_mean:.0}",
            deviation * 100.0,
        );
    }

    /// The reused domain check is an upper bound only: it accepts the
    /// zero vector. The relations of the construction ask for
    /// `0 < ||s||`, so that half has to be checked separately, and
    /// every caller of `check_domain` pairs it with `is_non_zero`.
    /// Report: Step 2 and Step 3 of the issuing protocol.
    #[test]
    fn the_reused_bound_check_accepts_a_zero_preimage() {
        let sampler = toy_sampler(1);
        let (a, _) = sampler.trap_gen();
        let zero = MatPolyOverZ::new(a.get_num_columns(), 1);
        assert!(
            sampler.check_domain(&zero),
            "the reused check is an upper bound and does accept zero",
        );
        assert!(!sampler.is_non_zero(&zero));
    }

    /// The toy width has to clear the smoothing bound of its own
    /// basis, or `key_gen` would refuse it.
    #[test]
    fn the_toy_width_meets_the_smoothing_condition() {
        let sampler = toy_sampler(1);
        let (_, trapdoor) = sampler.trap_gen();
        assert!(sampler.width_meets_smoothing(&trapdoor));
        assert!(f64::try_from(sampler.width()).unwrap() >= sampler.least_width(&trapdoor));
    }

    /// A width below the smoothing bound is detected rather than
    /// silently accepted. This is the failure the report records in
    /// "A Parameter That Was Silently Wrong".
    #[test]
    fn a_width_below_the_smoothing_bound_is_detected() {
        let sampler = toy_sampler(1);
        let (_, trapdoor) = sampler.trap_gen();
        let narrow = Sampler::new(gadget_parameters(D, Q_MOD, 1), Q::from(1), Q::from(1.005_f64));
        assert!(!narrow.width_meets_smoothing(&trapdoor));
    }

    #[test]
    fn the_bound_matches_the_dimensions() {
        for sampling in Sampling::ALL {
            let sampler = toy_sampler_with(1, sampling);
            let (a, _) = sampler.trap_gen();
            let expected = Q::from(100 * 100 * a.get_num_columns() * D);
            assert_eq!(expected, sampler.preimage_bound_sqrd(), "{sampling}");
        }
    }
}
