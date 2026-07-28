# blind-sig

A prototype of the round-optimal lattice-based blind signature described in
the report chapter *A Blind Signature from GenISIS_f*. The issuing protocol
has one round: the user sends a commitment together with a proof of knowledge
of its opening, and the signer returns a function input, function randomness,
and a short preimage.

This README is written to be followed from a fresh copy of the source, with no
prior setup.

## Quick start on Windows

The prototype is built on qFALL, whose FLINT binding does not support the
native Windows toolchain: its build script stops with *"Windows MSVC target is
not supported (linking would fail)"*. Use the Windows Subsystem for Linux
instead. On an x86-64 machine this is a native Linux environment, not an
emulated one, so **everything in this project runs there, including the LaZer
proof layer**.

Install WSL once, from PowerShell as administrator, and reboot if prompted:

```powershell
wsl --install -d Ubuntu
```

Then open the Ubuntu terminal and run everything below inside it. Copy the
source into the Linux filesystem rather than working under `/mnt/c`, which is
much slower:

```sh
cp -r /mnt/c/Users/<you>/Downloads/blind-sig ~/blind-sig
cd ~/blind-sig
```

Install the toolchain:

```sh
sudo apt-get update
sudo apt-get install -y build-essential curl git cmake unzip patch
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

Install Rust with the `rustup` script above rather than from the
distribution: this crate uses edition 2024 and needs Rust 1.85 or
newer, while `apt install cargo` on Ubuntu 24.04 gives 1.75.

GMP and MPFR are not in the package list on purpose. qFALL depends on
`gmp-mpfr-sys`, which builds both from source during the first Cargo
build, so no developer package and no root access is needed. Step 2
reuses that copy. Installing `libgmp-dev` and `libmpfr-dev` also works
if you have the rights to.

Now go to *Step 1* below.

## Step 1: the scheme and its tests (any platform, about a minute)

```sh
cargo test
```

This runs 55 tests: 50 unit tests and 5 integration tests in
`tests/protocol.rs`. It covers key generation, the commitment, the issuing
protocol, the native Fiat--Shamir proof, finalisation, and verification. No
LaZer libraries are needed, because the crate's `lazer-ffi` feature is off by
default.

The first build compiles FLINT from source and takes a few minutes.

A demo of one full protocol run, followed by both public functions:

```sh
cargo run --bin blind-sig
```

Step timings and size estimates:

```sh
cargo run --release --bin bench
```

The demo and the benchmark use toy parameters (`d = 8`, `q = 257`) and are not
cryptographically sized.

## Step 2: the LaZer-backed proof layer (x86-64 only)

Run *Step 1* first. Besides checking that the scheme works, it builds
the GMP and MPFR that LaZer needs to compile, and the script below
picks that copy up.

The two NIZK proof systems of the construction, `Pi_com` and `Pi_sig`, are
also implemented on top of the LaZer library. LaZer is pinned to the revision
in `lazer/LAZER_REVISION`, which supports x86-64. One script fetches it,
applies two patches for bugs in that revision, and builds the static
libraries:

```sh
scripts/build-lazer.sh
```

It refuses to run on other architectures and says so. When it finishes it
prints the exact command to run the tests, which is:

```sh
LAZER_INCLUDE_DIR=.lazer-src LAZER_LIB_DIR=.lazer-src LAZER_HEXL_LIB_DIR=.lazer-src/third_party/hexl-development/build/hexl/lib cargo test --features lazer-ffi -- --test-threads=1
```

Single-threaded, because LaZer keeps process-wide state behind a one-time
initialiser. This adds the tests in `tests/lazer_protocol.rs`, which run the
issuing protocol with a LaZer `Pi_com`, produce a `Pi_sig` proof that hides
the witness, and check that both are rejected when the statement changes.

`lazer/README.md` documents the two patches, the generated parameter
profiles, and how to regenerate them with SageMath.

### On Apple Silicon

The LaZer layer cannot be built or run on an arm64 Mac. Emulating x86-64
there is unreliable: `rustc` itself crashes under both of Docker Desktop's
emulation backends, which is a known container issue rather than a problem
with this code
([rustup#3902](https://github.com/rust-lang/rustup/issues/3902),
[docker/for-mac#7006](https://github.com/docker/for-mac/issues/7006)).
Step 1 runs normally. The layer is verified on a native x86-64 runner by
`.github/workflows/lazer.yml`; those steps are executed on every push, so they
cannot drift from the code.

## Layout

```text
src/public_function.rs   the interface f: K x M x X -> R_q^n
src/hash_to_ring.rs      f(kappa, mu, xi) = H(sep|kappa|mu|xi)
src/binary_encoding.rs   the fixed function of BLNS, Section 3.1.2
src/module_lwe.rs        f(kappa, mu, xi) = kappa xi + G enc(mu)
src/commitment.rs        c = B_1 m + B_2 r
src/proof_com.rs         Fiat--Shamir with aborts for the opening relation
src/commitment_proof.rs  Pi_com providers: Fiat--Shamir and LaZer
src/keys.rs              key generation over a chosen public function
src/issue.rs             the one-round issuing protocol
src/signature.rs         finalisation, verification, and Pi_sig providers
src/lazer_ffi.rs         the safe boundary to the two LaZer profiles
lazer/                   pinned revision, patches, C shims, and profiles
scripts/build-lazer.sh   builds the pinned LaZer static libraries
```

Each proof system is reached through a provider trait, so the native
Fiat--Shamir proof and the LaZer proof are interchangeable at the call site.

## Which public function to use

`ModuleLweEncoding` is the instantiation the LaZer proofs need. Both of its
terms are linear in their hidden argument, so the final-signature relation
stays linear over `R_q`, with `enc(mu)` as a binary witness and `xi` as a
short one. `HashToRing` cannot be used with `Pi_sig`: proving
`H(sep|kappa|mu|xi)` for hidden `mu` and `xi` is a statement about a hash
circuit, which a proof system of this kind does not express. The transparent
signature path in `src/signature.rs` works for every public function but
provides no blindness.

## Status

Implemented: the scheme, the commitment, the issuing protocol, both proof
layers, and the three instantiations of `f`. Not implemented: straight-line
extraction for `Pi_com`, which the security analysis assumes and Fiat--Shamir
does not provide. The parameters used by the demo and the benchmark are toy
values, not the output of a parameter search.
