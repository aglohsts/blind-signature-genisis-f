# LaZer integration

This directory holds everything that connects the prototype to LaZer: the
pinned revision, the patches that revision needs, the C shims, and the two
generated parameter profiles.

The main README explains how to build LaZer and how to run the tests. This
file covers only what lives here.

## Contents

| File | Purpose |
|---|---|
| `LAZER_REVISION` | the pinned LaZer commit |
| `patches/` | two fixes the pinned revision needs |
| `params_d64.py`, `params_d64.h` | the profile for the commitment relation |
| `params_sig_d64.py`, `params_sig_d64.h` | the profile for the final-signature relation |
| `shim.c`, `shim.h` | the C boundary for the commitment proof |
| `shim_sig.c` | the C boundary for the final-signature proof |
| `shim_sig_statement.c`, `shim_sig_statement.h` | builds the final-signature statement for LaZer |
| `Dockerfile` | builds the libraries and regenerates the profiles |
| `probe_small_q.py` | helper used when searching for a modulus |

## The two patches

The pinned revision has two bugs that stop the proof layer from working.

`0001-pass-input-equations-to-tbox.patch`. The revision stores
caller-supplied equations after its internal reserved slots, but its
high-level prover and verifier pass the reserved slots to the t-box. The
patch makes both paths use the caller's equations.

`0002-initialise-sparse-encoding.patch`. The sparse statement encoder leaves
part of its first output byte uninitialised. The transcript hash then
depends on unrelated heap contents, so verification fails unpredictably. The
patch initialises the byte.

## The two profiles

LaZer generates a proof system ahead of time from a description of a
relation, so each relation becomes one profile. `params_d64.py` covers the
commitment relation of `Pi_com`, and `params_sig_d64.py` covers the
final-signature relation of `Pi_sig`. Chapter 7 of the report explains both
relations, and why the second one needs the algebraic `f`.

Both profiles use `d = 64` and the same 58-bit modulus
`q = 288230376151713349`, so one public key serves both proofs. The modulus
is not chosen directly. The generator for the final-signature profile is
given a bit length and picks its own prime, so a test asserts that the two
profiles agree rather than reading the value from the sources.

Two details are not visible in the generated headers.

The commitment relation has ten witness slots, but only the first four are
used, for `(m_0, m_1, r_0, r_1)`. The other six are padding, and the shim
fixes their matrix columns and witness values to zero. LaZer's completeness
condition at degree 64 requires the padding, and it does not change the
commitment equation.

The number of exact l2 proofs shifts the offset at which LaZer stores
caller-supplied equations. `shim_sig_statement.h` records this next to the
constant that carries the value.

**The revision, the profiles and the shims must be changed together.** The
proof lengths are compile-time constants, and the Rust tests assert them:
24,696 bytes for `Pi_com`, and 27,008 bytes as the declared maximum for
`Pi_sig`. Both change whenever a profile changes.

## Building the libraries with Docker

This is an alternative to building LaZer by hand. The build is
`linux/amd64`, which matches the pinned revision.

```sh
docker build --platform linux/amd64 --file lazer/Dockerfile \
    --target library-artifacts --output type=local,dest=.lazer .
```

It writes:

```text
.lazer/include/lazer.h
.lazer/lib/liblazer.a
.lazer/lib/libhexl.a
.lazer/metadata/LAZER_REVISION
```

Set `LAZER_INCLUDE_DIR=.lazer/include`, and use `.lazer/lib` for both
`LAZER_LIB_DIR` and `LAZER_HEXL_LIB_DIR`.

## Regenerating the profiles

This is the only step that needs SageMath, which is why it uses Docker.
Build the generator image:

```sh
docker build --platform linux/amd64 --file lazer/Dockerfile \
    --target parameter-generator --tag blind-sig-lazer-params .
```

Then run it from the project root:

```sh
docker run --rm --platform linux/amd64 --volume "$PWD:/project" \
    blind-sig-lazer-params lin-codegen.sage \
    /project/lazer/params_d64.py > lazer/params_d64.h

docker run --rm --platform linux/amd64 --volume "$PWD:/project" \
    blind-sig-lazer-params lnp-tbox-codegen.sage \
    /project/lazer/params_sig_d64.py > lazer/params_sig_d64.h
```
