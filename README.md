# blind-sig-genisis-f-prototype

A prototype of the round-optimal lattice-based blind signature described in
the report chapter *A Blind Signature from GenISIS_f*. 
The issuing protocol has one round. 
The user sends a commitment together with a proof that it knows how to open it. 
The signer returns a function input, a function randomness, and a short preimage.

The prototype treats the public function `f` as a pluggable component, and
three instantiations are provided. 
It also carries two proof systems for the commitment relation, 
one written for this project and one built on LaZer.

Chapter 7 of the report explains the design. Chapter 8 reports the
measurements, and the appendix lists the modules and the tests.

## Libraries

| Library | Use | Where to get it |
|---|---|---|
| qFALL (`qfall-math`, `qfall-tools`, `qfall-schemes`) | ring arithmetic, Gaussian sampling, gadget trapdoors, SHA-256 into `R_q^n` | <https://qfall.github.io> |
| LaZer | zero-knowledge proof systems | <https://github.com/lazer-crypto/lazer> |
| Rust toolchain | edition 2024, so version 1.85 or newer | <https://rustup.rs> |

qFALL is fetched by Cargo, so it needs no separate installation. LaZer is
a C library and is not on crates.io, so its source is vendored in
`third_party/lazer` at a pinned revision and `build.rs` builds it; see
*The LaZer-backed proof layer* below. Nothing is fetched from the network
at build time.

## Environment

**The prototype needs Linux on x86-64 to run in full.** 
The limit comes from the reused libraries and not from the scheme.

* **x86-64, not arm64.** The pinned LaZer revision targets x86-64. Its
  header `lazer.h` includes `immintrin.h`, so on arm64 the C compiler stops
  with *"This header is only meant to be used on x86 and x64 architecture"*
  before it reads any project code.

The scheme runs anywhere qFALL runs, including an arm64 Mac. 
Only the LaZer proof layer is restricted.

The reference machine is Ubuntu 24.04 LTS with GCC 13 and rustc 1.93.

## Checking that the tools are present

Run these before anything else. Every command must print a version.

```sh
uname -s -m                          # expect: Linux x86_64
rustc --version && cargo --version   # expect: 1.85 or newer
cc --version && make --version       # qFALL compiles C sources during the build
```

A C toolchain is needed even though the prototype is written in Rust. qFALL
depends on `flint-sys` and `gmp-mpfr-sys`, and both compile FLINT, GMP and
MPFR from source during the first Cargo build. GMP and MPFR are therefore
not needed as system packages, and the LaZer build can reuse the copy that
Cargo produced, so the project builds without root access.

Building LaZer needs `cmake`, `make`, `patch` and `unzip` in addition.
`build.rs` checks for each of these before it starts and names the one
that is missing, rather than failing part-way through a build.

## Running the prototype

### The scheme and its tests

```sh
cargo test
```

This runs 71 tests: 64 unit tests and 7 integration tests. It needs no LaZer
libraries, because the `lazer-ffi` feature is off by default. The first build
compiles FLINT, GMP and MPFR from source and takes 10 to 20 minutes.

An interactive run, which prints the 4 protocol steps and then checks the
signature against a different message so that the rejection is visible:

```sh
cargo run --release --bin blind-sig -- "hello world"
```

```text
Key setup (once)                        kappa = 807    137.25 ms

message: hello world
  message as bits          0011001010111100
  Step 1  user -> signer   sends c and the proof          0.10 ms
  Step 2  signer -> user   sends mu, xi and s             7.11 ms
          mu = 476155, xi = 471
  Step 3  user checks it                     accepted      0.05 ms
  Step 4  anyone verifies                    ACCEPTED      0.05 ms
          same signature, message "hello world " -> rejected, as it should be
```

These are toy parameters (`d = 8`, `q = 257`) and are not
cryptographically sized. Chapter 8 of the report gives the full timings and
sizes.

### The two preimage samplers

The prototype carries 2 preimage samplers, and a key records which one it
uses. What differs is *when* the short basis is orthogonalised, not what is
sampled. Both draw a fresh, independent preimage on every call.

| Sampler | Orthogonalises the short basis | Cost |
|---|---|---|
| `stored` (default) | once, at key generation | key generation is slow, each signature is fast |
| `per-call` | again on every call, as the qFALL sampler does | each signature carries a full orthogonalisation |

They are interchangeable. They sample the same distribution over the same
coset, and a signature made under one is accepted by a verifier using the
other.

`cargo test` covers both without any flag, so the run above already tested
them. Seven tests take each mode in turn: four in `src/preimage.rs` and two
in `tests/protocol.rs` loop over both modes, and one more signs under one
sampler and verifies under the other, in both directions. Two of these are
worth naming. `repeated_samples_under_one_trapdoor_differ` checks that two
calls on one trapdoor and one target give different preimages, which is
what "fresh sample" means here.
`the_stored_basis_samples_the_same_distribution` compares the mean squared
norm of 60 samples from each mode, which is evidence that storing the basis
changed the timing and not the output.

To see the difference rather than test it:

```sh
cargo run --release --bin blind-sig -- --sampler=per-call "hello world"
cargo run --release --bin bench
cargo run --release --bin parameters -- 64 288230376151713349 256
```

- `bench` reports the step timings and compares the two samplers.
- `parameters` reports the gadget base, the Gaussian parameter, the norm
bound and the modulus that the proof system needs.

### The LaZer-backed proof layer

The two NIZK proof systems are built on LaZer, a C library. Its source is
in `third_party/lazer`, at the revision pinned in `lazer/LAZER_REVISION`,
so nothing is fetched from the network and one command builds and runs
everything:

```sh
cargo test --release --features lazer-ffi -- --test-threads=1
```

Single-threaded, because LaZer keeps process-wide state behind a one-time
initialiser. This adds 14 tests. The C library is built on the first run
and takes 5 to 15 minutes; after that it is cached with the rest of the
build. Key generation at `d = 64` then dominates the run, so the suite
takes 20 to 30 minutes and is quiet for long stretches.

Beyond the toolchain above, this needs `cmake`, `make`, `patch` and
`unzip`. `build.rs` checks for each before it starts and names the one
that is missing.

#### What that command does

The steps are worth knowing, because two of them are not obvious and both
are discussed in the report. `build.rs` performs them in order, printing
as it goes:

1. **Copy** `third_party/lazer` into Cargo's output directory. The
   vendored copy stays untouched, and a failed build can be restarted by
   deleting `target`.
2. **Apply** `lazer/patches/*.patch`. The pinned revision has two defects
   that stop the proof layer working, and `lazer/README.md` explains
   both. They are kept as patches rather than shipped pre-applied, so
   that what was changed can be read in two short files.
   Each patch is then checked by counting a line it inserts, because a
   half-patched tree compiles without complaint and fails later inside
   the proof layer, which is much harder to diagnose.
3. **Build the vendored HEXL** with `cmake`, passing
   `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`. LaZer's own Makefile builds HEXL
   too, but without that option, and HEXL declares a
   `cmake_minimum_required` that CMake 4 refuses. The error without it is
   unclear, which is why this step is taken here instead.
4. **Run `make lib-static`**, with `CPATH` and `LIBRARY_PATH` pointed at
   the GMP and MPFR that `gmp-mpfr-sys` built during step 1 of this
   README. Those are the two libraries LaZer needs, and a shared machine
   often has neither installed; reusing Cargo's copy means the build
   needs no root.

#### Reusing a LaZer tree that is already built

Set all three of these and `build.rs` will link against that tree instead
of building the vendored one:

```sh
LAZER_INCLUDE_DIR=<dir with lazer.h> \
LAZER_LIB_DIR=<dir with liblazer.a> \
LAZER_HEXL_LIB_DIR=<dir with libhexl.a> \
cargo test --release --features lazer-ffi -- --test-threads=1
```

Setting some but not all three is an error rather than a partial
override, so a stale variable cannot silently half-apply.

`lazer/README.md` documents the two patches, the two generated parameter
profiles, and how to regenerate them with SageMath.

## Layout

```text
src/public_function.rs         the interface f: K x M x X -> R_q^n
src/hash_to_ring.rs            f(kappa, mu, xi) = H(sep|kappa|mu|xi)
src/binary_encoding.rs         the fixed function of BLNS, Section 3.1.2
src/module_lwe.rs              f(kappa, mu, xi) = kappa xi + G enc(mu)
src/commitment.rs              c = B_1 m + B_2 r
src/preimage.rs                trapdoor and preimage sampling, both samplers
src/proof_com.rs               Fiat--Shamir with aborts for the opening relation
src/commitment_proof.rs        Pi_com providers: Fiat--Shamir and LaZer
src/keys.rs                    key generation over a chosen public function
src/issue.rs                   the one-round issuing protocol
src/signature.rs               finalisation, verification, and Pi_sig providers
src/lazer_ffi.rs               the safe boundary to the two LaZer profiles
src/util.rs                    the two norms used by every bound check
src/main.rs                    the interactive demo
src/bin/bench.rs               step timings and size estimates
src/bin/parameters.rs          the width, bound and modulus a base implies
lazer/                         patches, C shims, and the two proof profiles
third_party/lazer/             the pinned LaZer source, unmodified
build.rs                       builds LaZer, then compiles and links the shims
tests/protocol.rs              the protocol through the public interface
tests/lazer_protocol.rs        the same, with both proofs produced by LaZer
```

## Status

Implemented: the scheme, the commitment, the issuing protocol, both proof
layers, both preimage samplers, and three instantiations of `f`.

Not implemented: straight-line extraction for `Pi_com`, which the security
analysis assumes and Fiat--Shamir does not provide. The parameters used by
the demo and the benchmark are toy values and are not the output of a
parameter search.
