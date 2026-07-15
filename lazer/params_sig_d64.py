"""LaZer d=64 final-signature profile. Report: "The Final-Signature Proof"."""

from math import sqrt

name = "blind_sig_sig_d64"

d = 64
log2q = 48

preimage_length = 51
randomness_length = 2
preimage_gaussian_width = 100
preimage_bound_sq = preimage_gaussian_width**2 * preimage_length * d
randomness_bound_sq = 2_000

m1 = preimage_length + randomness_length
alpha = sqrt(preimage_bound_sq + randomness_bound_sq)

# m stores the binary tag, its preimage norm, and a modular inverse.
l = 3
nbin = 1

n = [preimage_length, randomness_length]
B = [sqrt(preimage_bound_sq), sqrt(randomness_bound_sq)]

# This zero-valued ARP keeps the pinned advanced prover on its initialised path.
nprime = 1
Bprime = 1
