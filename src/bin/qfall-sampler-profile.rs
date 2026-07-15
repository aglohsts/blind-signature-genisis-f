//! Manual profile for the advanced qFALL conditioned sampler.
//! Report: "Remaining Work".

use blind_sig::keys::{KeyGenParams, key_gen};
use blind_sig::proof_com::ComProofParams;
use blind_sig::tag_function::{BinaryEncoding, TagFunction};
use qfall_math::integer::{MatPolyOverZ, PolyOverZ, Z};
use qfall_math::rational::Q;
use qfall_math::traits::{MatrixDimensions, MatrixSetEntry};
use qfall_tools::primitive::psf::{PSF, PSFGPVRing};
use qfall_tools::sample::g_trapdoor::gadget_parameters::GadgetParametersRing;
use std::io::{self, Write};
use std::time::Instant;

const DEGREE: i64 = 64;
const MODULUS: u64 = 281_474_976_711_349;

fn main() {
    let started = Instant::now();
    let psf = PSFGPVRing {
        gp: GadgetParametersRing::init_default(DEGREE, MODULUS),
        s: Q::from(100),
        s_td: Q::from(1.005_f64),
    };
    let f = BinaryEncoding::new(1, DEGREE, psf.gp.modulus.clone());
    let (pk, sk) = key_gen(
        f,
        psf,
        KeyGenParams {
            ell_m: 2,
            ell_r: 2,
            s_r: Q::from(3),
            beta_msg_sqrd: Z::from(16),
            beta_r_sqrd: Z::from(2_000),
            com_params: ComProofParams {
                witness_inf: 20,
                mask_inf: 8_000,
            },
        },
    );
    println!(
        "key generation: {:.3} s; preimage dimension: {}",
        started.elapsed().as_secs_f64(),
        pk.a.get_num_columns() * DEGREE,
    );

    let mut message = MatPolyOverZ::new(2, 1);
    message.set_entry(0, 0, PolyOverZ::from(1)).unwrap();
    let randomness = MatPolyOverZ::new(2, 1);
    let commitment = pk.ck.commit(&message, &randomness);
    let target = &pk.f.eval(&Z::ONE) + &commitment;

    println!("starting qFALL conditioned preimage sampling");
    io::stdout().flush().unwrap();
    let sampling_started = Instant::now();
    let preimage = pk.psf.samp_p(&pk.a, &sk.trapdoor, &target);
    println!(
        "conditioned sampling: {:.3} s",
        sampling_started.elapsed().as_secs_f64(),
    );
    assert!(pk.psf.check_domain(&preimage));
    assert_eq!(target, pk.psf.f_a(&pk.a, &preimage));
}
