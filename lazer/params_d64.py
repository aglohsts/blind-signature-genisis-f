"""LaZer d=64 profile. Report: "LaZer Integration Feasibility"."""

from math import sqrt

vname = "blind_sig_com_d64"

deg = 64
# Matches the advanced final-signature statement ring.
mod = 281_474_976_711_349
dim = (1, 10)

# The witness layout and zero padding are defined in the report.
wpart = [[0, 1], [2, 3], [4, 5, 6, 7, 8, 9]]
wl2 = [sqrt(16), sqrt(2000), 0]
wbin = [0, 0, 1]

# Toy integration bound; not a final cryptographic parameter.
wlinf = 20
