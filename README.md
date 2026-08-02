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
  NIZK proof systems, targets x86-64 and does not build for arm64. Its
  public header `lazer.h` includes `immintrin.h`, so on arm64 the C
  compiler stops at *"This header is only meant to be used on x86 and x64
  architecture"* before any project code is reached. This is a property of
  the library, not of this project, so no change here works around it.

Neither limit comes from the scheme. Both come from a reused library, and
together they leave no platform other than Linux on x86-64 on which the
whole project runs.

| | Linux x86-64 | Linux arm64 / macOS arm64 | Windows (native) |
|---|---|---|---|
| The scheme and its tests (*Step 1*) | yes | yes | no |
| The LaZer proof layer (*Step 2*) | yes | no | no |
| Evaluation figures reported in the project | yes | partial | no |

The scheme itself is therefore portable across everything qFALL supports,
including an arm64 Mac, and only the proof layer is restricted. See *Other
platforms* at the end for what does and does not work elsewhere.

### Checking the machine

Run this first. Both lines must be as shown before *Step 2* will work:

```sh
uname -s -m
```

```text
Linux x86_64
```

`aarch64` or `arm64` in place of `x86_64` means *Step 1* will run and
*Step 2* will not. *Step 2.1* checks this before anything is built.

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
Cargo build. *Step 2.3* then reuses that copy: it looks for `mpfr.h` on the
system, and when that is missing it points the compiler and linker at the
one Cargo built under `target/`.

The practical consequence is that **the whole project builds without root
access**, which matters on a departmental machine. Installing `libgmp-dev`
and `libmpfr-dev` also works and is slightly faster, if you have the rights
to.

`gcc-14` is optional. *Step 2.7* uses it when it is on the path, and the
default compiler otherwise.

### Disk, memory and time

| | |
|---|---|
| Disk, `target/` after both steps | about 1.5 GB |
| Disk, `.lazer-src/` after *Step 2* | about 0.5 GB |
| First `cargo test` (compiles FLINT, GMP and MPFR from source) | 10 to 20 minutes |
| Later `cargo test` runs | a few seconds |
| Building LaZer (*Step 2*) | 5 to 15 minutes |
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
cargo run --release --bin parameters -- 64 288230376151713349 256
```

Without the trailing base it sweeps every base, which is only affordable
at a small degree; it warns when it is run below degree 64, because a
width read at a smaller degree is an underestimate.

## Step 2: the LaZer-backed proof layer (Linux, x86-64)

The two NIZK proof systems of the construction, `Pi_com` and `Pi_sig`, are
also implemented on top of the LaZer library. LaZer is pinned to the
revision in `lazer/LAZER_REVISION`. Building it takes 5 to 15 minutes and
has seven steps.

Run *Step 1* first. Besides checking that the scheme works, it builds the
GMP and MPFR that LaZer needs in order to compile, and *Step 2.3* below
picks that copy up.

### 2.1 Check the architecture

```sh
uname -m
```

This must print `x86_64`. The pinned LaZer revision does not build on
arm64, and the failure is not graceful: `lazer.h` includes `immintrin.h`,
so the compiler stops with *"This header is only meant to be used on x86
and x64 architecture"*. Stop here if the output is `aarch64` or `arm64`.

### 2.2 Check the tools

```sh
for t in git make cmake unzip patch; do command -v $t || echo "MISSING: $t"; done
```

All five must be present. See *Installing the toolchain* above.

### 2.3 Point the compiler at GMP and MPFR

Check whether the headers are already on the system:

```sh
printf '#include <mpfr.h>\nint main(void){return 0;}\n' | cc -x c -fsyntax-only -
```

If that prints nothing, the headers are present and this step is done.
If it fails, use the copy that Cargo built during *Step 1*:

```sh
export CPATH=$(dirname $(find target -path '*gmp-mpfr-sys*/out/include/mpfr.h' | head -1))
export LIBRARY_PATH=$(dirname $CPATH)/lib
echo "CPATH=$CPATH"
```

If `find` returns nothing, *Step 1* has not been run yet. Run `cargo test`
first. Installing `libgmp-dev` and `libmpfr-dev` also works, if you have
the rights to.

### 2.4 Fetch the pinned revision

```sh
git init .lazer-src
git -C .lazer-src remote add origin https://github.com/lazer-crypto/lazer.git
git -C .lazer-src fetch --depth 1 origin $(cat lazer/LAZER_REVISION)
git -C .lazer-src checkout --detach FETCH_HEAD
git -C .lazer-src submodule update --init --recursive
```

`.lazer-src` is excluded by `.gitignore` and takes about 0.5 GB.

### 2.5 Apply the two patches

The pinned revision has two bugs that stop the proof layer from working.
`lazer/README.md` explains both.

```sh
for p in lazer/patches/*.patch; do patch --directory=.lazer-src --strip=1 --input="$p"; done
```

### 2.6 Build the vendored HEXL

This is built before LaZer itself, because the vendored copy declares an
old `cmake_minimum_required` that CMake 4 no longer accepts. The last
option below overrides that.

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

`touch hexl-development` stops `make` from repeating the step later.
Check the result before going on:

```sh
ls .lazer-src/third_party/hexl-development/build/hexl/lib/libhexl.a
```

### 2.7 Build the static library

```sh
make -C .lazer-src lib-static
```

Use `gcc-14` instead if it is on the path, which is faster:

```sh
make -C .lazer-src CC=gcc-14 CXX=g++-14 lib-static
```

Check the result:

```sh
ls .lazer-src/liblazer.a
```

### 2.8 Run the LaZer-backed tests

```sh
LAZER_INCLUDE_DIR=.lazer-src LAZER_LIB_DIR=.lazer-src LAZER_HEXL_LIB_DIR=.lazer-src/third_party/hexl-development/build/hexl/lib cargo test --release --features lazer-ffi -- --test-threads=1
```

Single-threaded, because LaZer keeps process-wide state behind a one-time
initialiser. This adds 14 tests: 11 unit tests in `src/lazer_ffi.rs` that
exercise both generated profiles directly, and 3 integration tests in
`tests/lazer_protocol.rs` that run the issuing protocol with a LaZer
`Pi_com`, produce a `Pi_sig` proof that hides the witness, and check that
both are rejected when the statement changes.

`lazer/README.md` documents the two patches, the generated parameter
profiles, and how to regenerate them with SageMath. Regeneration is the
one step that uses Docker, because it needs a pinned SageMath image. The
build above does not.

## Evaluation: reproducing the evidence set

These are the manual steps used to generate the results reported in the
Evaluation chapter: the environment, parameter derivation, the test
suites, a worked protocol run, and the step timings.

To keep a record rather than only reading the output, append
`2>&1 | tee -a evidence.log` to each command. **The output produced on
the reference environment is the record that the LaZer layer works**, so
run *Step 4* on the Linux machine and keep it.

### Before you start

Run all commands from the project root:

```sh
cd path/to/blind-sig
```

If the LaZer libraries are built, export their paths once so the later
commands stay simple. Check which layout you have — *Step 2* writes
`.lazer-src`, and the Docker recipe in `lazer/README.md` exports to
`.lazer`:

```sh
ls .lazer-src/liblazer.a 2>/dev/null || ls .lazer/lib/liblazer.a 2>/dev/null
```

If `.lazer-src` exists:

```sh
export LAZER_INCLUDE_DIR=.lazer-src
export LAZER_LIB_DIR=.lazer-src
export LAZER_HEXL_LIB_DIR=.lazer-src/third_party/hexl-development/build/hexl/lib
```

If `.lazer` exists instead:

```sh
export LAZER_INCLUDE_DIR=.lazer/include
export LAZER_LIB_DIR=.lazer/lib
export LAZER_HEXL_LIB_DIR=.lazer/lib
```

If neither exists, skip *Step 4* and note this in the report.

### 1. Environment

Record the machine and toolchain used for the run:

```sh
date -u
uname -a
rustc --version
git rev-parse --short HEAD
```

When the LaZer libraries are built, also record which revision they came
from:

```sh
cat lazer/LAZER_REVISION
```

### 2. Parameter derivation

The parameters are not chosen; they follow from three linked conditions.
The gadget base fixes the preimage length and the basis size that key
generation must orthogonalise. The base also fixes the basis's
coarseness, and Klein's sampler is correct only above the largest
Gram-Schmidt norm times a smoothing factor (GPV, STOC 2008). That width
fixes the norm bound in the relation, and the proof system is
knowledge-sound only above roughly its square (Lyubashevsky-Nguyen-
Plancon 2022). The ring degree is fixed at d = 64 by the proof system's
generator.

```sh
cargo run --release --bin parameters -- 8 288230376151713349
```

The arguments are `[degree] [modulus] [base]`. Here `8` is the ring
degree the sweep runs at and `288230376151713349` is the modulus used in
the report. With no third argument the tool tries every gadget base,
which is only affordable at a small degree; it prints a warning when it
runs below degree 64, because a width read at a smaller degree is an
underestimate. Once a base is picked, read the real width at the degree
the proof layer uses:

```sh
cargo run --release --bin parameters -- 64 288230376151713349 256
```

This prints, for each gadget base: the preimage length, the minimum
width the smoothing condition allows, the resulting norm bound at
degree 64, the modulus the proof system needs, and the
orthogonalisation time.

### 3. Test suite, without LaZer

```sh
cargo test --release
```

Takes under a minute once the dependencies are built. The *first* build
compiles FLINT, GMP and MPFR from source and takes 10 to 20 minutes; see
the table in *Disk, memory and time*.

### 4. Test suite, with the LaZer proof layer (optional)

Uses the environment variables set above. Single-threaded, since LaZer
keeps process-wide state behind a one-time initialiser; key generation
at degree 64 dominates the runtime.

> **Note:** this step takes 20-30 minutes, the longest step in this
> section. No output for long stretches is expected and does not mean
> it has stalled.

```sh
cargo test --release --features lazer-ffi -- --test-threads=1
```

If LaZer is not built, skip this step and note it in the report.

### 5. Worked protocol run, under each sampler

Both samplers sign and verify the same message; only the timings
differ.

```sh
cargo run --release --bin blind-sig -- --sampler=stored "hello world" "hello world"
cargo run --release --bin blind-sig -- --sampler=per-call "hello world" "hello world"
```

`"hello world"` is the sample message used in the report and can be
replaced with any other string. Each argument is signed in turn, so
passing the same message twice signs it twice: the transcript differs
each time, which is the freshness blindness rests on.

### 6. Step timings and size estimates

```sh
cargo run --release --bin bench
```

Takes a few minutes.

### 7. Scope of these results

These steps show that the scheme runs, that both proof systems accept
its relations, and what each step costs at the parameters above.

They do not establish a security level. The message space, commitment
randomness bound, and function-input space are toy values, and no
hardness estimator was run for the underlying assumption. The proof
system's own generator reports reductions for the proofs themselves,
visible in the generated profile headers.

The security argument also assumes straight-line extraction for the
commitment proof. Neither proof layer provides this.

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

Run *Step 2* and the evaluation steps on the Linux machine instead.

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
src/bin/parameters.rs          the width, bound and modulus a base implies
lazer/                         pinned revision, patches, C shims, and profiles
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
