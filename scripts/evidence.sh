#!/bin/sh
# Produces the whole evidence set in one run: the environment it was
# taken on, where every parameter comes from, the test suites, a worked
# protocol run, and the step timings. Report: "Evaluation".
#
# Usage: scripts/evidence.sh [output-file]
#
# The LaZer sections are included when the libraries are present and
# skipped with a note when they are not, so the script produces a
# complete record on any platform and says what is missing.

set -eu

project="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project"
output="${1:-evidence-$(date +%Y%m%d-%H%M%S).log}"

# Two layouts produce the libraries: scripts/build-lazer.sh writes the
# LaZer source tree to .lazer-src, and the Docker recipe in lazer/README.md
# exports headers and archives to .lazer. Accept either.
have_lazer=no
if [ -f "$project/.lazer-src/liblazer.a" ] \
    && [ -f "$project/.lazer-src/third_party/hexl-development/build/hexl/lib/libhexl.a" ]; then
    have_lazer=yes
    include_dir="$project/.lazer-src"
    lib_dir="$project/.lazer-src"
    hexl="$project/.lazer-src/third_party/hexl-development/build/hexl/lib"
elif [ -f "$project/.lazer/lib/liblazer.a" ] && [ -f "$project/.lazer/lib/libhexl.a" ]; then
    have_lazer=yes
    include_dir="$project/.lazer/include"
    lib_dir="$project/.lazer/lib"
    hexl="$project/.lazer/lib"
fi

section() {
    printf '\n========================================================\n'
    printf '%s\n' "$1"
    printf '========================================================\n\n'
}

{
    section "1. Environment"
    printf 'date        : %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf 'machine     : %s %s\n' "$(uname -s)" "$(uname -m)"
    printf 'cpu cores   : %s\n' "$(getconf _NPROCESSORS_ONLN)"
    printf 'rustc       : %s\n' "$(rustc --version)"
    printf 'commit      : %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')"
    printf 'branch      : %s\n' "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '-')"
    printf 'LaZer libs  : %s\n' "$have_lazer"
    if [ "$have_lazer" = yes ]; then
        printf 'LaZer commit: %s\n' "$(cat lazer/LAZER_REVISION)"
    fi

    section "2. Where the parameters come from"
    cat <<'NOTE'
Each value below is the output of a stated condition, not a choice, and
the three conditions constrain one another:

  the gadget base fixes the preimage length, and so the size of the
  basis key generation has to orthogonalise;

  the base also fixes how coarse that basis is, and Klein's sampler is
  correct only above the largest Gram-Schmidt norm of the basis times a
  smoothing factor (GPV, STOC 2008);

  that width fixes the norm bound the relation states, and the proof
  system is knowledge-sound only above roughly the square of it
  (Lyubashevsky-Nguyen-Plancon 2022, checked by its own generator).

The ring degree is not chosen at all: the proof system's generator
carries the constant d = 64 and refuses a lower degree.

The columns below are, for each gadget base: the preimage length, the
least width the smoothing condition allows, the norm bound that width
implies at degree 64, the modulus the proof system would then need, and
how long the one-off orthogonalisation takes.
NOTE
    printf '\n'
    cargo run --release --quiet --bin parameters -- 8 288230376151713349 2>&1 \
        | grep -v '^WARNING: A completely filled' || true

    section "3. Test suite, without LaZer"
    cargo test --release 2>&1 | grep -vE '^\s*$'

    if [ "$have_lazer" = yes ]; then
        section "4. Test suite, with the LaZer proof layer"
        printf 'Single-threaded: LaZer keeps process-wide state behind a\n'
        printf 'one-time initialiser. Key generation at degree 64 dominates.\n\n'
        LAZER_INCLUDE_DIR="$include_dir" \
        LAZER_LIB_DIR="$lib_dir" \
        LAZER_HEXL_LIB_DIR="$hexl" \
        cargo test --release --features lazer-ffi -- --test-threads=1 --nocapture 2>&1 \
            | grep -v '^WARNING: A completely filled' || true
    else
        section "4. Test suite, with the LaZer proof layer  [SKIPPED]"
        printf 'The pinned LaZer libraries are not built in this checkout.\n'
        printf 'Run scripts/build-lazer.sh first; it needs x86-64.\n'
    fi

    section "5. A worked protocol run, under each preimage sampler"
    printf 'The two samplers are interchangeable: the same message is signed\n'
    printf 'and verified under each, and only the timings differ.\n'
    for sampler in stored per-call; do
        printf '\n--- sampler: %s ---\n\n' "$sampler"
        cargo run --release --quiet --bin blind-sig -- \
            "--sampler=$sampler" "hello world" "hello world" 2>&1
    done

    section "6. Step timings and size estimates, toy parameters"
    cargo run --release --quiet --bin bench 2>&1

    section "7. What these numbers do and do not establish"
    cat <<'NOTE'
They establish that the scheme runs, that both proof systems accept the
relations of the construction, and what each step costs at the
parameters above.

They do not establish a security level. The message space, the
commitment randomness bound and the function-input space are toy values
and no hardness estimator was run for the assumption the scheme reduces
to. The proof system's own generator does report reductions for the
proofs themselves, and those appear in the generated profile headers.

The security argument also assumes straight-line extraction for the
commitment proof, which neither proof layer provides.
NOTE
} 2>&1 | tee "$output"

printf '\nwritten to %s\n' "$output"
