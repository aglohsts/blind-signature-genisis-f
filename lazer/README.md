# LaZer integration profile

The integration is pinned to the commit stored in `LAZER_REVISION`.
The Docker build reads this file directly, so the revision is not repeated in
the build recipe or the generated parameter headers.

The pinned revision stores caller-supplied equations after internal reserved
slots, but its high-level prover and verifier pass the reserved slots to the
t-box. The Docker build applies
`patches/0001-pass-input-equations-to-tbox.patch` so both paths use the
caller-supplied equations.

The sparse statement encoders also leave the first output byte partly
uninitialised. The build applies
`patches/0002-initialise-sparse-encoding.patch` to make transcript hashes
independent of prior heap contents.

Both profiles use the ring `d = 64`, `q = 281474976711349`, so one public key
serves both proofs. The toy demo stays at `d = 8` and does not enable LaZer.

## The two relations

`params_d64.py` is the source profile for the commitment relation of
`Pi_com`:

```text
[B_1 | B_2] * [m; r] - c = 0.
```

The generated relation has ten witness slots. The first four are
`(m_0, m_1, r_0, r_1)`; the remaining six are binary padding slots whose
matrix columns and witness values are fixed to zero by the shim. This padding
is required by LaZer's completeness condition at degree 64 and does not alter
the commitment equation.

`params_sig_d64.py` is the source profile for the final-signature relation of
`Pi_sig`. With the algebraic public function
`f(kappa, mu, xi) = kappa xi + G enc(mu)`, the relation
`A s = f(kappa, mu, xi) + B_1 m + B_2 r` becomes

```text
A s - kappa xi - B_2 r - G enc(mu) - B_1 m = 0,
```

which is linear in the hidden values. The bounded witness is the
concatenation `(s, xi, r)` with three exact l2 proofs; `enc(mu)` is the
binary witness; and the public message `m` moves into the constant offset.
`shim_sig_statement.c` emits one evaluation equation per coefficient of the
ring equation, plus two equations that bind an unbounded variable to the
squared norm of `s` and force that norm to have a modular inverse. Together
they give the requirement `0 < ||s||` of the relation.

The third l2 block is what distinguishes this profile from a fixed-function
one. It also moves LaZer's `EVALEQ_INPUT_OFF`, because that offset counts
`2 * Z + 1` reserved slots for `Z` exact l2 proofs; `BS_SIG_D64_L2_PROOFS`
carries the same value.

## Build the C libraries

The Docker build is intentionally `linux/amd64`, matching the architecture
supported by the pinned LaZer revision. Export the header and static libraries
to the ignored `.lazer` directory with:

```sh
docker build --platform linux/amd64 --file lazer/Dockerfile --target library-artifacts --output type=local,dest=.lazer .
```

The resulting layout is:

```text
.lazer/include/lazer.h
.lazer/include/src/moduli.h
.lazer/lib/liblazer.a
.lazer/lib/libhexl.a
.lazer/metadata/LAZER_REVISION
```

For Cargo builds, set `LAZER_INCLUDE_DIR=.lazer/include` and use `.lazer/lib`
as both `LAZER_LIB_DIR` and `LAZER_HEXL_LIB_DIR`. The `lazer-ffi` feature then
compiles the shims, links the exported libraries, and exposes both profiles
through `blind_sig::lazer_ffi`.

The shims own all LaZer-specific types; the Rust side sees only `i64`
coefficient slices. They validate the checked-in norm bounds before calling
LaZer and prevent the verifier from passing a short proof to LaZer's
lengthless decoder. For `Pi_com`, LaZer's parameter length is treated as a
fixed 22,682-byte transport buffer, with unused bytes zeroed and checked as
canonical padding.

## Run the Rust integration tests

Build the reusable Linux/AMD64 runner, which contains the pinned LaZer build
and the native libraries needed by qFALL:

```sh
docker build --platform linux/amd64 --file lazer/Dockerfile --target rust-runner --tag blind-sig-lazer-rust .
```

From the project root, mount the working tree and two persistent Cargo caches:

```sh
docker run --rm --platform linux/amd64 --volume "$PWD:/project" --volume blind-sig-cargo-registry:/usr/local/cargo/registry --volume blind-sig-cargo-target:/cargo-target blind-sig-lazer-rust
```

The first qFALL/FLINT build can take around 20 minutes. Later runs reuse the
named Docker volumes. The runner overrides the ignored, machine-specific
`.cargo/config.toml`, so an Apple Silicon host still builds the Linux/AMD64
target used by LaZer.

## Regenerate the parameters

Build the pinned SageMath image with the generator scripts from the pinned
LaZer source stage:

```sh
docker build --platform linux/amd64 --file lazer/Dockerfile --target parameter-generator --tag blind-sig-lazer-params .
```

Generate the checked-in headers from the project root:

```sh
docker run --rm --platform linux/amd64 --volume "$PWD:/project" blind-sig-lazer-params lin-codegen.sage /project/lazer/params_d64.py > lazer/params_d64.h
```

```sh
docker run --rm --platform linux/amd64 --volume "$PWD:/project" blind-sig-lazer-params lnp-tbox-codegen.sage /project/lazer/params_sig_d64.py > lazer/params_sig_d64.h
```

Generated headers, source profiles, the LaZer revision, and their shims must
be reviewed and updated together. The proof lengths asserted by the Rust tests
(22,682 and 32,234 bytes) change whenever a profile changes.
