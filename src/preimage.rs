//! Preimage sampling with a stored orthogonalised basis.
//! Report: "The Two Components Do Not Meet".
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

/// A trapdoor together with everything derived from it that does not
/// depend on the target.
pub struct Trapdoor {
    pub r: MatPolyOverZ,
    pub e: MatPolyOverZ,
    basis: MatZ,
    basis_gso: MatQ,
    rotated_a: MatZq,
}

/// A preimage sampler over `R_q`.
pub struct Sampler {
    psf: PSFGPVRing,
}

impl Sampler {
    pub fn new(parameters: GadgetParametersRing, width: Q, trapdoor_width: Q) -> Sampler {
        Sampler {
            psf: PSFGPVRing {
                gp: parameters,
                s: width,
                s_td: trapdoor_width,
            },
        }
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
            a,
            Trapdoor {
                r,
                e,
                basis,
                basis_gso,
                rotated_a,
            },
        )
    }

    /// Samples a short `s` with `A s = target`.
    pub fn samp_p(&self, trapdoor: &Trapdoor, target: &MatPolynomialRingZq) -> MatPolyOverZ {
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

    /// The largest Gram-Schmidt norm of the stored basis. Klein's
    /// sampler is only correct for a width above this times a
    /// smoothing factor, so it is what decides the width, and a
    /// coarser gadget raises it.
    pub fn max_gso_norm(&self, trapdoor: &Trapdoor) -> Q {
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
    /// `2^-64`; `max_gso_norm` returns the squared norm, so the
    /// square root is taken here.
    pub fn least_width(&self, trapdoor: &Trapdoor) -> f64 {
        let dimension = trapdoor.basis_gso.get_num_rows() as f64;
        let epsilon = 2.0_f64.powi(-64);
        let smoothing = ((2.0 * dimension * (1.0 + 1.0 / epsilon)).ln()
            / std::f64::consts::PI)
            .sqrt();
        let squared: f64 = f64::try_from(&self.max_gso_norm(trapdoor)).unwrap_or(f64::NAN);
        squared.sqrt() * smoothing
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
        Sampler::new(
            gadget_parameters(D, Q_MOD, log_base),
            Q::from(100),
            Q::from(1.005_f64),
        )
    }

    #[test]
    fn a_sample_solves_the_equation_and_respects_the_bound() {
        let sampler = toy_sampler(1);
        let (a, trapdoor) = sampler.trap_gen();
        let target = MatPolynomialRingZq::sample_uniform(1, 1, sampler.modulus());

        let preimage = sampler.samp_p(&trapdoor, &target);
        assert_eq!(target, sampler.f_a(&a, &preimage));
        assert!(sampler.check_domain(&preimage));
        assert!(sampler.is_non_zero(&preimage));
    }

    /// The stored basis is reused, so repeated calls under one
    /// trapdoor must keep working and must not repeat themselves.
    #[test]
    fn repeated_samples_under_one_trapdoor_differ() {
        let sampler = toy_sampler(1);
        let (a, trapdoor) = sampler.trap_gen();
        let target = MatPolynomialRingZq::sample_uniform(1, 1, sampler.modulus());

        let first = sampler.samp_p(&trapdoor, &target);
        let second = sampler.samp_p(&trapdoor, &target);
        assert_eq!(target, sampler.f_a(&a, &first));
        assert_eq!(target, sampler.f_a(&a, &second));
        assert_ne!(first, second, "the sampler must not be deterministic");
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

    #[test]
    fn the_bound_matches_the_dimensions() {
        let sampler = toy_sampler(1);
        let (a, _) = sampler.trap_gen();
        let expected = Q::from(100 * 100 * a.get_num_columns() * D);
        assert_eq!(expected, sampler.preimage_bound_sqrd());
    }
}
