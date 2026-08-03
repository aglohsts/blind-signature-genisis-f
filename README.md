# blind-sig-genisis-f-prototype

A prototype of the round-optimal lattice-based blind signature described in
the report chapter *A Blind Signature from GenISIS_f*. The issuing protocol
has one round. The user sends a commitment together with a proof that it
knows how to open it. The signer returns a function input, a function
randomness, and a short preimage.

The prototype treats the public function `f` as a pluggable component, and
three instantiations are provided. It also carries two proof systems for the
commitment relation, one written for this project and one built on LaZer.

Chapter 7 of the report explains the design. Chapter 8 reports the
measurements, and the appendix lists the modules and the tests.

## Libraries

| Library | Use | Where to get it |
|---|---|---|
| qFALL (`qfall-math`, `qfall-tools`, `qfall-schemes`) | ring arithmetic, Gaussian sampling, gadget trapdoors, SHA-256 into `R_q^n` | <https://qfall.github.io> |
| LaZer | the two lattice zero-knowledge proof systems | <https://github.com/lazer-crypto/lazer> |
| Rust toolchain | edition 2024, so version 1.85 or newer | <https://rustup.rs> |

qFALL is fetched by Cargo, so it needs no separate installation. LaZer is a
C library and must be built by hand; see *Building LaZer* below.

## Environment

**The prototype needs Linux on x86-64 to run in full.** Both limits come
from the reused libraries and not from the scheme.

* **Linux, not Windows.** qFALL depends on FLINT, whose Rust binding rejects
  the native Windows toolchain. Use the Windows Subsystem for Linux instead.
* **x86-64, not arm64.** The pinned LaZer revision targets x86-64. Its
  header `lazer.h` includes `immintrin.h`, so on arm64 the C compiler stops
  with *"This header is only meant to be used on x86 and x64 architecture"*
  before it reads any project code.

The scheme itself runs anywhere qFALL runs, including an arm64 Mac. Only the
LaZer proof layer is restricted.

| | Linux x86-64 | arm64 (Linux or macOS) | Windows (native) |
|---|---|---|---|
| The scheme and its tests | yes | yes | no |
| The LaZer proof layer | yes | no | no |

The reference machine is Ubuntu 24.04 LTS with GCC 13 and rustc 1.93.

## Checking that the tools are present

Run these before anything else. Every command must print a version.

```sh
uname -s -m                                  # expect: Linux x86_64
rustc --version && cargo --version           # expect: 1.85 or newer
cc --version && make --version               # C toolchain
cmake --version && git --version             # for building LaZer
unzip -v | head -1 && patch --version | head -1
```

GMP and MPFR are **not** needed as system packages. qFALL builds both from
source on the first Cargo build, and the LaZer build reuses that copy, so
the whole project builds without root access.

## Running the prototype

### The scheme and its tests

```sh
cargo test
```

This runs 71 tests: 64 unit tests and 7 integration tests. It needs no LaZer
libraries, because the `lazer-ffi` feature is off by default. The first build
compiles FLINT, GMP and MPFR from source and takes 10 to 20 minutes.

An interactive run, which prints the four protocol steps and then checks the
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

The prototype carries two preimage samplers. The `stored` sampler
orthogonalises the short basis once, at key generation. The `per-call`
sampler repeats that work on every call, which is what the reused qFALL
sampler does. They are interchangeable, and a signature made under one is
accepted under the other.

```sh
cargo run --release --bin blind-sig -- --sampler=per-call "hello world"
cargo run --release --bin bench
cargo run --release --bin parameters -- 64 288230376151713349 256
```

`bench` reports the step timings and compares the two samplers.
`parameters` reports the gadget base, the Gaussian parameter, the norm
bound, and the modulus that the proof system then needs.

### Building LaZer

LaZer is pinned to the revision in `lazer/LAZER_REVISION`. Building it takes
5 to 15 minutes. Check the architecture first, because the build fails late
otherwise.

```sh
uname -m                                     # must print x86_64
```

If `mpfr.h` is not on the system, point the compiler at the copy that Cargo
built during `cargo test`:

```sh
printf '#include <mpfr.h>\nint main(void){return 0;}\n' | cc -x c -fsyntax-only -
export CPATH=$(dirname $(find target -path '*gmp-mpfr-sys*/out/include/mpfr.h' | head -1))
export LIBRARY_PATH=$(dirname $CPATH)/lib
```

Fetch the pinned revision:

```sh
git init .lazer-src
git -C .lazer-src remote add origin https://github.com/lazer-crypto/lazer.git
git -C .lazer-src fetch --depth 1 origin $(cat lazer/LAZER_REVISION)
git -C .lazer-src checkout --detach FETCH_HEAD
git -C .lazer-src submodule update --init --recursive
```

Apply the two patches. That revision has two bugs that stop the proof layer
from working, and `lazer/README.md` explains both:

```sh
for p in lazer/patches/*.patch; do patch --directory=.lazer-src --strip=1 --input="$p"; done
```

Build the vendored HEXL first. Its `cmake_minimum_required` is too old for
CMake 4, so the last option below overrides that check:

```sh
cd .lazer-src/third_party
unzip -q -o hexl-development.zip
cmake -S hexl-development -B hexl-development/build \
    -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build hexl-development/build -j"$(nproc)"
touch hexl-development
cd ../..
```

`touch hexl-development` stops `make` from repeating the step. Then build
the static library, using `gcc-14` if it is on the path:

```sh
make -C .lazer-src lib-static
ls .lazer-src/liblazer.a
```

### The LaZer-backed tests

```sh
LAZER_INCLUDE_DIR=.lazer-src \
LAZER_LIB_DIR=.lazer-src \
LAZER_HEXL_LIB_DIR=.lazer-src/third_party/hexl-development/build/hexl/lib \
cargo test --release --features lazer-ffi -- --test-threads=1
```

Single-threaded, because LaZer keeps process-wide state behind a one-time
initialiser. This adds 14 tests. Key generation at `d = 64` dominates the
runtime, so the suite takes 20 to 30 minutes and is quiet for long
stretches.

`lazer/README.md` documents the two patches, the generated parameter
profiles, and how to regenerate them with SageMath. Regeneration is the only
step that needs Docker.

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
lazer/                         pinned revision, patches, C shims, and profiles
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
