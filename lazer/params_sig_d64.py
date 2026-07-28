"""LaZer d=64 final-signature profile. Report: "The Final-Signature Proof".

The relation proved is

    A s - kappa xi - B_2 r - G enc(mu) = B_1 m,

with the public message m on the right. The bounded witness is the
concatenation (s, xi, r); the binary witness is enc(mu). Compared with
the fixed-function profile this adds the third exact l2 block for the
function randomness xi, which is what makes the keyed and probabilistic
function provable.
"""

from math import sqrt

name = "blind_sig_sig_d64"

d = 64
log2q = 48

preimage_length = 51
function_randomness_length = 2
randomness_length = 2
preimage_gaussian_width = 100
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
