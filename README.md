# blind-sig-genisis-f-prototype

This is a prototype of the round-optimal lattice-based blind signature
described in the report chapter *A Blind Signature from GenISIS_f*.

The issuing protocol has one round. The user sends a commitment and a
proof that it knows how to open that commitment. The signer replies with
a function input, a function randomness, and a short preimage.

The public function `f` is a pluggable component, and three versions of
it are provided. There are also two proof systems for the commitment
relation. One is written for this project, and one is built on LaZer.

Chapter 7 of the report explains the design. Chapter 8 gives the
measurements, and the appendix lists the modules and the tests.

## Libraries

| Library | Use | Where to get it |
|---|---|---|
| qFALL (`qfall-math`, `qfall-tools`, `qfall-schemes`) | ring arithmetic, Gaussian sampling, gadget trapdoors, SHA-256 into `R_q^n` | <https://qfall.github.io> |
| LaZer | zero-knowledge proof systems | <https://github.com/lazer-crypto/lazer> |
| Rust toolchain | edition 2024, so version 1.85 or newer | <https://rustup.rs> |

Cargo downloads qFALL, so you do not need to install it yourself.

LaZer is a C library and is not on crates.io. Its source code is included
in this project, in `third_party/lazer`, at one fixed revision. `build.rs`
builds it for you. Nothing is downloaded from the internet during the
build.

## Environment

**You need Linux on x86-64 to run the whole project.** This limit comes
from the libraries it reuses, not from the scheme itself.

* **Linux, not Windows.** The FLINT binding used by qFALL does not
  support the native Windows toolchain. Its build script stops with the
  message *"Windows MSVC target is not supported (linking would fail)"*.
  You can use the Windows Subsystem for Linux instead. On an x86-64
  machine, WSL is a real Linux environment and not an emulated one, so
  everything here works inside it.
* **x86-64, not arm64.** The fixed LaZer revision is written for x86-64.
  Its header `lazer.h` includes `immintrin.h`. On arm64, the C compiler
  stops with the message *"This header is only meant to be used on x86
  and x64 architecture"* before it reads any project code.

Step 2 below runs on any machine that qFALL supports, including an arm64
Mac. Only Step 3, the LaZer proof layer, has these limits.

The reference machine is Ubuntu 24.04 LTS with 8 x86-64 cores, GCC 13 and
rustc 1.97.

## How long this takes

Two steps below take a long time, and both are silent while they run. The
times come from the reference machine.

| Step | First run | Later runs |
|---|---|---|
| 1. Install the toolchain | 5 min | — |
| 2. `cargo test` | 10 to 20 min, because it compiles FLINT, GMP and MPFR | a few seconds |
| 3. `cargo test --features lazer-ffi` | 5 to 15 min to build LaZer, then 20 to 30 min to run | 20 to 30 min |

Step 3 is slow because it generates one key at ring degree 64, and that
alone takes about 16 minutes. If it prints nothing for 15 minutes,
nothing is wrong.

## Step 1: install the toolchain

On Ubuntu or Debian:

```sh
sudo apt-get update
```

```sh
sudo apt-get install -y build-essential curl cmake unzip patch
```

On other systems you need a C and C++ compiler, `make`, `cmake`, `unzip`
and `patch`. University machines usually have all of them already.

Next, install Rust. Please use `rustup` and not the package from your
distribution. This project uses edition 2024 and needs Rust 1.85 or
newer, but `apt install cargo` on Ubuntu 24.04 gives version 1.75.
`rustup` installs into your home directory, so you do not need root
access.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

```sh
. "$HOME/.cargo/env"
```

**GMP and MPFR are not in the list above, and this is on purpose.** qFALL
depends on `flint-sys` and `gmp-mpfr-sys`, and these compile FLINT, GMP
and MPFR from source during Step 2. The LaZer build in Step 3 then reuses
that copy. This means you do not need them as system packages, and the
whole project builds without root access.

### Check before you start

Each command below should print a version number. `build.rs` checks for
the same tools before it starts and tells you which one is missing, but
it is faster to find out now.

```sh
uname -s -m
```

```sh
rustc --version && cargo --version
```

```sh
cc --version | head -1 && make --version | head -1 && cmake --version | head -1
```

The first command must print `Linux x86_64`. The second must print 1.85
or a later version.

## Step 2: the scheme and its tests

```sh
cargo test
```

This runs 71 tests: 64 unit tests and 7 integration tests. It does not
need LaZer, because the `lazer-ffi` feature is off by default. The last
lines should be:

```text
test result: ok. 64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

You can also run the protocol yourself. The command below prints the 4
protocol steps. It then checks the signature against a different message,
so that you can see the rejection happen.

```sh
cargo run --release --bin blind-sig -- "hello world"
```

The program first explains what a blind signature is and what each step
does. It then prints this:

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

These are toy parameters (`d = 8`, `q = 257`). They are not
cryptographically sized. Chapter 8 of the report gives the full timings
and sizes.

## Step 3: the LaZer proof layer

The two zero-knowledge proof systems are built on LaZer. Its source code
is in `third_party/lazer`, at the revision listed in
`lazer/LAZER_REVISION`. Nothing is downloaded, so **one command builds
the library and runs the tests**:

```sh
cargo test --release --features lazer-ffi -- --test-threads=1
```

The tests run one at a time because LaZer keeps state for the whole
process behind a setup function that runs only once. You also need
`--release` here. In a debug build, the key generation at degree 64 takes
several hours.

The first message you see comes from the build script:

```text
warning: building the LaZer library from third_party/lazer. This runs once
and takes 5 to 15 minutes.
```

This is normal. Cargo gives build scripts no other way to print a
message, so the text appears as a warning.

After that, the tests run for 20 to 30 minutes. They end with 85 tests,
which is 14 more than Step 2:

```text
test result: ok. 75 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

During the run, LaZer prints this line many times:

```text
WARNING: A completely filled lookup table will exceed 2^16 entries.
```

This comes from the discrete Gaussian sampler in qFALL, at the width that
this profile uses. It is harmless.

To see the timing of each stage and the size of the proof at degree 64,
add `--nocapture` to the flags that are already there. These are the
figures reported in Chapter 8.

```sh
cargo test --release --features lazer-ffi -- --test-threads=1 --nocapture
```

### What that command does

It is useful to know these steps. Two of them are not obvious, and the
report discusses both. `build.rs` runs them in this order:

1. **Copy** `third_party/lazer` into the output folder of Cargo. The copy
   in `third_party` is never changed, so you can start again by deleting
   `target`.
2. **Apply** the patches in `lazer/patches`. The fixed LaZer revision has
   two bugs that stop the proof layer from working, and `lazer/README.md`
   explains both of them. The patches are applied here instead of being
   included in the source, so that you can read the changes in two short
   files. Each patch is then checked by counting a line that it adds. A
   tree with only some patches applied still compiles, and then fails
   inside the proof layer, which is much harder to debug.
3. **Build HEXL** with `cmake`, using the option
   `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`. The Makefile of LaZer also
   builds HEXL, but it does not pass this option. HEXL asks for a version
   of CMake that CMake 4 refuses, and the error message is not clear, so
   this step is done here instead.
4. **Run `make lib-static`**, with `CPATH` and `LIBRARY_PATH` set to the
   GMP and MPFR that Cargo built in Step 2. LaZer needs these two
   libraries, and a shared machine often has neither of them. Reusing the
   copy from Cargo means the build needs no root access.

### Using a LaZer build that already exists

If you set all three variables below, `build.rs` links against that build
instead of building the copy in `third_party`:

```sh
LAZER_INCLUDE_DIR=<folder with lazer.h> \
LAZER_LIB_DIR=<folder with liblazer.a> \
LAZER_HEXL_LIB_DIR=<folder with libhexl.a> \
cargo test --release --features lazer-ffi -- --test-threads=1
```

If you set only one or two of them, the build stops with an error. This
prevents an old variable from being used by mistake.

`lazer/README.md` describes the two patches, the two proof profiles, and
how to create the profiles again with SageMath.

## Starting again from a clean state

To remove everything that was built and start from nothing:

```sh
cargo clean && rm -rf .lazer-src .lazer
```

After this, Step 2 takes 10 to 20 minutes again, and Step 3 needs another
5 to 15 minutes to build LaZer. The folders `.lazer-src` and `.lazer`
only exist if you built LaZer by hand with an older version of this
project, so the command works whether they are there or not.

To rebuild LaZer but keep FLINT, which is much faster:

```sh
rm -rf target/*/build/blind-sig-*
```

## The two preimage samplers

This project has 2 preimage samplers, and each key records which one it
uses. The difference is *when* the short basis is made orthogonal, not
what is sampled. Both give a fresh, independent preimage on every call.

| Sampler | Makes the short basis orthogonal | Cost |
|---|---|---|
| `stored` (default) | once, during key generation | key generation is slow, each signature is fast |
| `per-call` | again on every call, like the qFALL sampler | every signature includes this work |

The two samplers can replace each other. They sample the same
distribution over the same coset, and a signature made with one is
accepted by a verifier that uses the other.

`cargo test` covers both of them without any flag, so Step 2 has already
tested them. Seven tests use each mode in turn. Four tests in
`src/preimage.rs` and two in `tests/protocol.rs` loop over both modes,
and one more signs with one sampler and verifies with the other, in both
directions.

Two of these tests are worth naming.
`repeated_samples_under_one_trapdoor_differ` checks that two calls with
one trapdoor and one target give different preimages, which is what a
fresh sample means here.
`the_stored_basis_samples_the_same_distribution` compares the mean
squared norm of 60 samples from each mode. This gives evidence that
storing the basis changed the speed and not the output.

To see the difference instead of testing it, run the demo with the slower
sampler. Compare its `Step 2` line with the one in Step 2 above.

```sh
cargo run --release --bin blind-sig -- --sampler=per-call "hello world"
```

The benchmark shows the timing of each step and compares the two
samplers. It takes about a minute.

```sh
cargo run --release --bin bench
```

The `parameters` tool shows how the parameters are fixed. For one gadget
base, it gives the preimage length, the smallest Gaussian width that the
sampler may use, the norm bound from that width, and the modulus that the
proof system then needs. Its output names every column.

```sh
cargo run --release --bin parameters
```

That command tries every base at ring degree 8 and takes about a minute.
To read the values at the degree that the proof system really uses, give
one base at a time. Each run takes about 16 minutes, because it builds a
trapdoor at degree 64 and makes its basis orthogonal.

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
third_party/lazer/             the fixed LaZer source, as published
build.rs                       builds LaZer, then compiles and links the shims
tests/protocol.rs              the protocol through the public interface
tests/lazer_protocol.rs        the same, with both proofs produced by LaZer
```

## Status

Done: the scheme, the commitment, the issuing protocol, both proof
layers, both preimage samplers, and three versions of `f`.

Not done: straight-line extraction for `Pi_com`. The security analysis
needs this property, and Fiat--Shamir does not provide it. The parameters
used by the demo and the benchmark are toy values. They are not the
result of a parameter search.
