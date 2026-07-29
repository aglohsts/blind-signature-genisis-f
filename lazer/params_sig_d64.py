"""LaZer d=64 final-signature profile. Report: "The Final-Signature Proof".

The relation proved is

    A s - kappa xi - B_2 r - G enc(mu) = B_1 m,

with the public message m on the right. The bounded witness is the
concatenation (s, xi, r); the binary witness is enc(mu). Compared with
the fixed-function profile this adds the third exact l2 block for the
function randomness xi, which is what makes the keyed and probabilistic
function provable.

The preimage length follows from the gadget base, and the width follows
from the base in turn. Base 256 gives a preimage of 10 ring elements
where base 2 gives 59, which is what brings the trapdoor's short basis
within reach of one orthogonalisation, and brings it there in about a
quarter of the time base 16 needs. A coarser gadget needs a wider
Gaussian: 3200 is above the smoothing bound of 3023 that this base
requires at degree 64, and the modulus is above the 2^56.0 that the
resulting norm bound forces on the proof system.

The width has to be read at degree 64 and not at a smaller one. The
Gram-Schmidt norms of the basis grow with the degree, so the same base
needs 1480 at degree 8 and 3023 at degree 64; taking the smaller figure
would put the sampler below its smoothing bound, where the output
distribution starts to depend on the basis. `cargo run --bin calibrate`
reports all of this, and warns when it is run below the target degree.
"""

from math import sqrt

name = "blind_sig_sig_d64"

d = 64
log2q = 58

preimage_length = 10
function_randomness_length = 2
randomness_length = 2
preimage_gaussian_width = 3200
preimage_bound_sq = preimage_gaussian_width**2 * preimage_length * d
function_randomness_bound_sq = 2_000
randomness_bound_sq = 2_000

m1 = preimage_length + function_randomness_length + randomness_length
alpha = sqrt(preimage_bound_sq + function_randomness_bound_sq + randomness_bound_sq)

# m stores the binary encoding of mu, the preimage norm, and a modular
# inverse of that norm. The inverse proves the norm is non-zero.
l = 3
nbin = 1

n = [preimage_length, function_randomness_length, randomness_length]
B = [
    sqrt(preimage_bound_sq),
    sqrt(function_randomness_bound_sq),
    sqrt(randomness_bound_sq),
]

# This zero-valued ARP keeps the pinned advanced prover on its initialised path.
nprime = 1
Bprime = 1
