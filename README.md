# blind-sig

A prototype of the round-optimal lattice-based blind signature described in
the report chapter *A Blind Signature from GenISIS_f*. The issuing protocol
has one round: the user sends a commitment together with a proof of knowledge
of its opening, and the signer returns a function input, function randomness,
and a short preimage.

This README is written to be followed from a fresh copy of the source, with no
prior setup.

## The reference environment: Linux on x86-64

**The prototype is developed and verified on Linux running on an x86-64
machine, and that is the environment every instruction below assumes.**
There are two independent reasons, and together they leave no other
platform on which the whole project runs:

* **Linux, not Windows.** The prototype is built on qFALL, whose FLINT
  binding rejects the native Windows toolchain: its build script stops
  with *"Windows MSVC target is not supported (linking would fail)"*.
* **x86-64, not arm64.** The pinned revision of LaZer, which supplies both
  NIZK proof systems, targets x86-64 and does not build for arm64.

The scheme itself (*Step 1*) is portable and runs on any platform qFALL
supports, including an arm64 Mac. Only the LaZer proof layer (*Step 2*)
needs x86-64. See *Other platforms* at the end for what does and does not
work elsewhere.

### Checking the machine

Run this first. Both lines must be as shown before *Step 2* will work:

```sh
uname -s -m
```

```text
Linux x86_64
```

`aarch64` or `arm64` in place of `x86_64` means *Step 1* will run and
*Step 2* will not; `scripts/build-lazer.sh` detects this and refuses with
an explanatory message rather than failing halfway through a build.

The reference environment is Ubuntu 24.04 LTS with GCC 13 and rustc 1.93.
Any reasonably current distribution works; nothing in the build depends on
the package manager beyond the compilers listed below.

### Installing the toolchain

```sh
sudo apt-get update
sudo apt-get install -y build-essential curl git cmake unzip patch
```

The equivalents on a non-Debian distribution are the C and C++ compilers,
`make`, `cmake`, `git`, `unzip` and `patch`. On a shared or departmental
machine these are usually installed already; check with
`cc --version && cmake --version && patch --version` before asking for
anything.

Then install Rust:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

Use the `rustup` script rather than the distribution's package. This crate
uses edition 2024 and needs Rust 1.85 or newer, while `apt install cargo`
on Ubuntu 24.04 gives 1.75. `rustup` installs entirely under `$HOME` and
needs no root, which is what makes it usable on a machine you do not
administer.

### What is deliberately not installed

**GMP and MPFR are absent from the package list on purpose.** qFALL depends
on `gmp-mpfr-sys`, which builds both libraries from source during the first
Cargo build. *Step 2* then reuses that copy: `scripts/build-lazer.sh` looks
for `mpfr.h` on the system, and when it is missing it finds the one Cargo
built under `target/` and points the compiler and linker at it.

The practical consequence is that **the whole project builds without root
access**, which matters on a departmental machine. Installing `libgmp-dev`
and `libmpfr-dev` also works and is slightly faster, if you have the rights
to.

`gcc-14` is optional. `scripts/build-lazer.sh` uses it when it is on the
path and falls back to the default compiler otherwise.

### Disk, memory and time

| | |
|---|---|
| Disk, `target/` after both steps | about 1.5 GB |
| Disk, `.lazer-src/` after *Step 2* | about 0.5 GB |
| First `cargo test` (compiles FLINT, GMP and MPFR from source) | 10 to 20 minutes |
| Later `cargo test` runs | a few seconds |
| `scripts/build-lazer.sh` | 5 to 15 minutes |
| The LaZer test suite, single-threaded | dominated by one key generation at `d = 64` |

Work in a local directory. A network-mounted home directory makes the
first build several times slower, because it is thousands of small file
writes.

## Step 1: the scheme and its tests (any platform)

```sh
cargo test
```

This runs 71 tests: 64 unit tests and 7 integration tests in
`tests/protocol.rs`. It covers key generation, the commitment, the issuing
protocol, the native Fiat--Shamir proof, finalisation, and verification, and
it does so under **both** preimage samplers (see *Choosing a preimage
sampler* below). No LaZer libraries are needed, because the crate's
`lazer-ffi` feature is off by default.

The first build compiles FLINT, GMP and MPFR from source; see the table
above for how long that takes.

An interactive run. Type a message and the four protocol steps are
reported with their timings, the signature is checked, and the same
signature is checked against a different message so that it visibly
fails:

```sh
cargo run --release --bin blind-sig
```

Messages can also be given as arguments, which signs each in turn and
exits. Signing one message twice shows a different transcript each
time, which is the freshness blindness rests on. The message space of
the toy parameters holds sixteen bits, so input is hashed into it
first.

Step timings, size estimates, and a side-by-side comparison of the two
preimage samplers:

```sh
cargo run --release --bin bench
```

The demo and the benchmark use toy parameters (`d = 8`, `q = 257`) and are not
cryptographically sized.

### Choosing a preimage sampler

The prototype carries two implementations of `SampPre`, and a key records
which one it uses:

| Mode | What it does | Cost |
|---|---|---|
| `stored` (default) | orthogonalises the short basis **once**, at key generation, and reuses it | key generation is expensive, each signature is cheap |
| `per-call` | rebuilds and orthogonalises the short basis **on every call**, which is what the reused qFALL sampler does as it is shipped | each signature carries a full orthogonalisation |

They are interchangeable: they sample the same distribution over the same
coset, and a signature made under either is accepted by the same verifier
under the same public key. The test suite asserts this — every claim about
an honest run is checked under both modes, and one test deliberately
verifies a `stored` signature with a `per-call` key and back.

The demo takes the mode on the command line:

```sh
cargo run --release --bin blind-sig -- --sampler=per-call "hello world"
```

```sh
cargo run --release --bin blind-sig -- --sampler=stored "hello world"
```

`cargo run --release --bin bench` reports both without being asked, because
the difference between them is the point:

```text
  sampler           key gen  signer response       one key + 20
  stored             118.02             6.67             251.39
  per-call            90.23           114.70            2384.27
```

Both modes orthogonalise the basis once at key generation, because `KeyGen`
checks the smoothing condition against it and that check is not skipped for
either mode. The per-call mode then pays for it again on every signature.
The ratio above is at `d = 8`; it grows quickly with the ring degree, and at
the `d = 64` the proof layer requires, `per-call` does not finish. That is
the obstacle *Step 2* exists to work around, and the LaZer integration test
asserts that its key uses `stored`.

The parameter chain behind the proof-layer profile — gadget base, least
Gaussian width, norm bound, and the modulus the proof system then needs —
is reported by:

```sh
cargo run --release --bin calibrate -- 64 288230376151713349 8
```

Without the trailing base it sweeps every base, which is only affordable
at a small degree; it warns when it is run below degree 64, because a
width read at a smaller degree is an underestimate.

## Step 2: the LaZer-backed proof layer (Linux, x86-64)

Run *Step 1* first. Besides checking that the scheme works, it builds
the GMP and MPFR that LaZer needs to compile, and the script below
picks that copy up.

The two NIZK proof systems of the construction, `Pi_com` and `Pi_sig`, are
also implemented on top of the LaZer library. LaZer is pinned to the revision
in `lazer/LAZER_REVISION`. One script fetches it, applies two patches for
bugs in that revision, builds the vendored HEXL, and builds the static
libraries:

```sh
scripts/build-lazer.sh
```

It checks the architecture first and refuses to run on anything but
x86-64, saying so. When it finishes it prints the exact command to run the
tests, which is:

```sh
LAZER_INCLUDE_DIR=.lazer-src LAZER_LIB_DIR=.lazer-src LAZER_HEXL_LIB_DIR=.lazer-src/third_party/hexl-development/build/hexl/lib cargo test --features lazer-ffi -- --test-threads=1
```

Single-threaded, because LaZer keeps process-wide state behind a one-time
initialiser. This adds 14 tests: 11 unit tests in `src/lazer_ffi.rs` that
exercise both generated profiles directly, and 3 integration tests in
`tests/lazer_protocol.rs` that run the issuing protocol with a LaZer
`Pi_com`, produce a `Pi_sig` proof that hides the witness, and check that
both are rejected when the statement changes.

`lazer/README.md` documents the two patches, the generated parameter
profiles, and how to regenerate them with SageMath. Regeneration is the one
step that uses Docker, because it needs a pinned SageMath image; the build
above does not.

## Producing the whole evidence set at once

One script runs everything in order and writes a single log: the
machine it ran on, where every parameter comes from, both test suites,
a worked protocol run, the step timings, and a note on what the numbers
do and do not establish.

```sh
scripts/evidence.sh
```

The LaZer sections are included when `scripts/build-lazer.sh` has been run
and skipped with a note when it has not, so the log is complete on any
platform and says what is missing from it. **The log produced on the
reference environment is the record that the LaZer layer works**, so run
this on the Linux machine after *Step 2* and keep the output.

## Other platforms

### macOS on Apple Silicon

*Step 1* runs normally. *Step 2* does not: the pinned LaZer revision needs
x86-64, and emulating it on an arm64 Mac is unreliable rather than merely
slow — `rustc` itself crashes under both of Docker Desktop's emulation
backends, which is a known container issue rather than a problem with this
code ([rustup#3902](https://github.com/rust-lang/rustup/issues/3902),
[docker/for-mac#7006](https://github.com/docker/for-mac/issues/7006)).
The C and C++ parts of the build, and the parameter generation, do run
correctly under that emulation, so the failure is confined to one
toolchain.

Run *Step 2* and `scripts/evidence.sh` on the Linux machine instead.

### Windows

Use the Windows Subsystem for Linux. On an x86-64 machine WSL is a native
Linux environment, not an emulated one, so everything in this project runs
there, including the LaZer proof layer.

```powershell
wsl --install -d Ubuntu
```

Open the Ubuntu terminal and follow *The reference environment* above
inside it. Copy the source into the Linux filesystem rather than working
under `/mnt/c`, which is much slower:

```sh
cp -r /mnt/c/Users/<you>/Downloads/blind-sig ~/blind-sig
cd ~/blind-sig
```

## Layout

```text
src/public_function.rs         the interface f: K x M x X -> R_q^n
src/hash_to_ring.rs            f(kappa, mu, xi) = H(sep|kappa|mu|xi)
src/binary_encoding.rs         the fixed function of BLNS, Section 3.1.2
src/module_lwe.rs              f(kappa, mu, xi) = kappa xi + G enc(mu)
src/commitment.rs              c = B_1 m + B_2 r
src/preimage.rs                trapdoor and preimage sampling: both the
                               stored-basis and the per-call samplers,
                               and the smoothing condition KeyGen checks
src/proof_com.rs               Fiat--Shamir with aborts for the opening relation
src/commitment_proof.rs        Pi_com providers: Fiat--Shamir and LaZer
src/keys.rs                    key generation over a chosen public function
src/issue.rs                   the one-round issuing protocol
src/signature.rs               finalisation, verification, and Pi_sig providers
src/signature/lazer_statement.rs  R_sig as a coefficient-level LaZer statement
src/lazer_ffi.rs               the safe boundary to the two LaZer profiles
src/util.rs                    the two norms used by every bound check
src/main.rs                    the interactive demo
src/bin/bench.rs               step timings and size estimates
src/bin/calibrate.rs           derives the width, bound and modulus chain
lazer/                         pinned revision, patches, C shims, and profiles
scripts/build-lazer.sh         builds the pinned LaZer static libraries
scripts/evidence.sh            runs everything and writes one log
tests/protocol.rs              the protocol through the public interface
tests/lazer_protocol.rs        the same, with both proofs produced by LaZer
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
layers, both preimage samplers, and the three instantiations of `f`. Not implemented: straight-line
extraction for `Pi_com`, which the security analysis assumes and Fiat--Shamir
does not provide. The parameters used by the demo and the benchmark are toy
values, not the output of a parameter search.
