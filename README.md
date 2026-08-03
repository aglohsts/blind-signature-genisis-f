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

* **Linux, not Windows.** qFALL's FLINT binding rejects the native
  Windows toolchain: its build script stops with *"Windows MSVC target is
  not supported (linking would fail)"*. The Windows Subsystem for Linux
  works, and on an x86-64 machine it is a native Linux environment rather
  than an emulated one, so everything here runs inside it.
* **x86-64, not arm64.** The pinned LaZer revision targets x86-64. Its
  header `lazer.h` includes `immintrin.h`, so on arm64 the C compiler stops
  with *"This header is only meant to be used on x86 and x64 architecture"*
  before it reads any project code.

The scheme runs anywhere qFALL runs, including an arm64 Mac. 
Only the LaZer proof layer is restricted.

The reference machine is Ubuntu 24.04 LTS on 8 x86-64 cores, with GCC 13
and rustc 1.97.

## How long the whole thing takes

Two of the steps below are long, and both are quiet while they run. The
figures are from the reference machine, an 8-core x86-64 Linux box.

| Step | First run | Later runs |
|---|---|---|
| 1. Install the toolchain | 5 min | — |
| 2. `cargo test` | 10 to 20 min, compiling FLINT, GMP and MPFR | a few seconds |
| 3. `cargo test --features lazer-ffi` | 5 to 15 min building LaZer, then 20 to 30 min running | 20 to 30 min |

Step 3 is long because it generates one key at ring degree 64, which
takes about 16 minutes on its own. Nothing is wrong if it prints nothing
for a quarter of an hour.

## Step 1: install the toolchain

On Ubuntu or Debian:

```sh
sudo apt-get update
sudo apt-get install -y build-essential curl cmake unzip patch
```

The equivalents elsewhere are a C and C++ compiler, `make`, `cmake`,
`unzip` and `patch`. On a departmental machine these are usually present
already.

Then install Rust. Use `rustup` rather than the distribution's package:
this crate uses edition 2024 and needs Rust 1.85 or newer, while
`apt install cargo` on Ubuntu 24.04 gives 1.75. `rustup` installs under
`$HOME` and needs no root.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```sh
. "$HOME/.cargo/env"
```

**GMP and MPFR are deliberately absent from that list.** qFALL depends on
`flint-sys` and `gmp-mpfr-sys`, which compile FLINT, GMP and MPFR from
source during Step 2. The LaZer build in Step 3 then reuses that copy, so
neither is needed as a system package and the whole project builds
without root access.

### Checking before you start

Every line here must print a version. `build.rs` checks the same tools
before it starts and names the one that is missing, but finding out now
is quicker.

```sh
uname -s -m
```

```sh
rustc --version && cargo --version
```

```sh
cc --version | head -1 && make --version | head -1 && cmake --version | head -1
```

The first must print `Linux x86_64`, and the second `1.85` or newer.

## Step 2: the scheme and its tests

```sh
cargo test
```

This runs 71 tests: 64 unit tests and 7 integration tests. It needs no
LaZer libraries, because the `lazer-ffi` feature is off by default, and
so it runs on any platform qFALL supports, including an arm64 Mac. The
last lines should read:

```text
test result: ok. 64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

An interactive run, which prints the 4 protocol steps and then checks the
signature against a different message so that the rejection is visible:

```sh
cargo run --release --bin blind-sig -- "hello world"
```

It opens with a description of what a blind signature is and what each
step does, and ends with the trace:

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

## Step 3: the LaZer-backed proof layer

The two NIZK proof systems are built on LaZer, a C library that is not on
crates.io. Its source is vendored in `third_party/lazer` at the revision
pinned in `lazer/LAZER_REVISION`, so nothing is fetched from the network
and **one command builds it and runs the tests**:

```sh
cargo test --release --features lazer-ffi -- --test-threads=1
```

Single-threaded, because LaZer keeps process-wide state behind a one-time
initialiser. `--release` is not optional here: a debug build of the
degree-64 key generation takes hours.

The first thing printed is a warning from the build script, which is the
only channel Cargo gives it:

```text
warning: building the LaZer library from third_party/lazer. This runs once
and takes 5 to 15 minutes.
```

That is expected, not a problem. After it, the suite runs for 20 to 30
minutes and ends with 85 tests, 14 more than Step 2:

```text
test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

To see the stage timings and the encoded proof size of the degree-64
run, which are the figures Chapter 8 reports, add `--nocapture` after the
flags that are already there:

```sh
cargo test --release --features lazer-ffi -- --test-threads=1 --nocapture
```

LaZer prints `WARNING: A completely filled lookup table will exceed 2^16
entries` many times during the run. It comes from qFALL's discrete
Gaussian sampler at the width this profile uses and is harmless.

### What that one command does

The steps are worth knowing, because two of them are not obvious and both
are discussed in the report. `build.rs` performs them in order:

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
   the GMP and MPFR that `gmp-mpfr-sys` built during Step 2. Those are the
   two libraries LaZer needs, and a shared machine often has neither
   installed; reusing Cargo's copy means the build needs no root.

### Reusing a LaZer tree that is already built

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

## The two preimage samplers

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

`cargo test` covers both without any flag, so Step 2 already tested
them. Seven tests take each mode in turn: four in `src/preimage.rs` and two
in `tests/protocol.rs` loop over both modes, and one more signs under one
sampler and verifies under the other, in both directions. Two of these are
worth naming. `repeated_samples_under_one_trapdoor_differ` checks that two
calls on one trapdoor and one target give different preimages, which is
what "fresh sample" means here.
`the_stored_basis_samples_the_same_distribution` compares the mean squared
norm of 60 samples from each mode, which is evidence that storing the basis
changed the timing and not the output.

To see the difference rather than test it, run the demo under the slower
sampler and compare the `Step 2` line with the one in Step 2 above:

```sh
cargo run --release --bin blind-sig -- --sampler=per-call "hello world"
```

The benchmark reports the step timings and puts the two samplers side by
side. It takes about a minute.

```sh
cargo run --release --bin bench
```

`parameters` reports the chain that fixes the parameters: for a given
gadget base, the preimage length, the least Gaussian width the sampler
may use, the norm bound that width gives, and the modulus the proof
system then needs. Each column is named in its own output.

```sh
cargo run --release --bin parameters
```

That sweeps every base at ring degree 8 and takes about a minute. Reading
it at the degree the proof system actually uses means one base at a time,
and about 16 minutes each, because it builds and orthogonalises a
degree-64 trapdoor:

```sh
cargo run --release --bin parameters -- 64 288230376151713349 256
```

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
third_party/lazer/             the pinned LaZer source, as published
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
