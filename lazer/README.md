# LaZer integration profile

The integration is pinned to the commit stored in `LAZER_REVISION`.
The Docker build reads this file directly, so the revision is not repeated in
the build recipe or the generated parameter header.

`params_d64.py` is the source profile for the commitment proof relation

```text
[B_1 | B_2] * [m; r] - c = 0.
```

It intentionally uses a separate integration ring (`d = 64`, `q = 257`)
because LaZer's linear-proof generator requires a power-of-two degree of at
least 64. The regular toy demo remains at `d = 8` and does not enable LaZer.

The generated relation has ten witness slots. The first four are
`(m_0, m_1, r_0, r_1)`; the remaining six are binary padding slots whose
matrix columns and witness values are fixed to zero by the shim. This padding
is required by LaZer's completeness condition at degree 64 and does not alter
the commitment equation.

## Build the C libraries

The Docker build is intentionally `linux/amd64`, matching the architecture
supported by the pinned LaZer revision. Export the header and static libraries
to the ignored `.lazer` directory with:

```sh
docker build --platform linux/amd64 \
  --file lazer/Dockerfile \
  --target library-artifacts \
  --output type=local,dest=.lazer \
  .
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
compiles `shim.c`, links the exported libraries, and exposes the fixed profile
through `blind_sig::lazer_ffi`.

The shim accepts four matrix/witness polynomials and owns all LaZer-specific
types. It pads the generated profile's other six columns with zero, validates
the checked-in message/randomness bounds, and prevents the verifier from
passing a short proof to LaZer's lengthless decoder. LaZer's parameter length
is treated as a fixed 16,166-byte transport buffer: unused bytes after its
variable-length encoding are zeroed and checked as canonical padding.

## Run the Rust integration tests

Build the reusable Linux/AMD64 runner, which contains the pinned LaZer build
and the native libraries needed by qFALL:

```sh
docker build --platform linux/amd64 \
  --file lazer/Dockerfile \
  --target rust-runner \
  --tag blind-sig-lazer-rust \
  .
```

From the project root, mount the working tree and two persistent Cargo caches:

```sh
docker run --rm --platform linux/amd64 \
  --volume "$PWD:/project" \
  --volume blind-sig-cargo-registry:/usr/local/cargo/registry \
  --volume blind-sig-cargo-target:/cargo-target \
  blind-sig-lazer-rust
```

The first qFALL/FLINT build can take around 20 minutes. Later runs reuse the
named Docker volumes. The runner overrides the ignored, machine-specific
`.cargo/config.toml`, so an Apple Silicon host still builds the Linux/AMD64
target used by LaZer.

## Regenerate the parameters

Build the pinned SageMath image with the generator scripts from the pinned
LaZer source stage:

```sh
docker build --platform linux/amd64 \
  --file lazer/Dockerfile \
  --target parameter-generator \
  --tag blind-sig-lazer-params \
  .
```

Generate the checked-in linear-proof header from the project root:

```sh
docker run --rm --platform linux/amd64 \
  --volume "$PWD:/project" \
  blind-sig-lazer-params \
  lin-codegen.sage /project/lazer/params_d64.py \
  > lazer/params_d64.h
```

The advanced LNP generator uses the same image with
`lnp-tbox-codegen.sage`. Generated headers, source profiles, the LaZer
revision, and their shims must be reviewed and updated together.
