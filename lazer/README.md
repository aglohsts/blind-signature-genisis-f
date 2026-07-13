# LaZer integration profile

The integration is pinned to the commit stored in `LAZER_REVISION`.

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
.lazer/lib/liblazer.a
.lazer/lib/libhexl.a
.lazer/metadata/LAZER_REVISION
```

For Cargo builds, use `.lazer/lib` as both `LAZER_LIB_DIR` and
`LAZER_HEXL_LIB_DIR`.

## Regenerate the parameters

Check out the revision from `LAZER_REVISION`, including its submodules. Then
generate the checked-in header with Sage 10.2. For example, from the project
root with the checkout path in `LAZER_CHECKOUT`:

```sh
docker run --rm --platform linux/amd64 \
  --volume "$LAZER_CHECKOUT:/lazer" \
  --volume "$PWD:/project" \
  --workdir /lazer/scripts \
  sagemath/sagemath:10.2 \
  sage lin-codegen.sage /project/lazer/params_d64.py \
  > lazer/params_d64.h
```

The generated header, LaZer source revision, and shim must be reviewed and
updated together.
