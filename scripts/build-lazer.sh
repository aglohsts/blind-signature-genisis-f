#!/bin/sh
# Builds the pinned LaZer static libraries and prints the environment the
# Cargo build script expects. x86-64 only; see README.md.
#
# Usage: scripts/build-lazer.sh [build-directory]
#
# The default build directory is ./.lazer-src, which .gitignore excludes.

set -eu

project="$(cd "$(dirname "$0")/.." && pwd)"
workdir="${1:-$project/.lazer-src}"
revision="$(cat "$project/lazer/LAZER_REVISION")"

case "$(uname -m)" in
x86_64 | amd64) ;;
*)
    echo "error: this machine is $(uname -m); the pinned LaZer revision" >&2
    echo "       supports x86-64 only. Run 'cargo test' instead, which" >&2
    echo "       covers the scheme without LaZer. See README.md." >&2
    exit 1
    ;;
esac

for tool in git make cmake unzip patch; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool is required but was not found" >&2
        exit 1
    }
done

# LaZer needs the GMP and MPFR headers. A machine without the developer
# packages still has them, because the qFALL dependency gmp-mpfr-sys
# builds both from source; reuse that copy rather than asking for root.
if ! printf '#include <mpfr.h>\nint main(void){return 0;}\n' \
    | "${CC:-cc}" -x c -fsyntax-only - >/dev/null 2>&1; then
    header="$(find "$project/target" -path '*gmp-mpfr-sys*/out/include/mpfr.h' \
        2>/dev/null | head -1)"
    if [ -z "$header" ]; then
        echo "error: mpfr.h was not found." >&2
        echo "       Run 'cargo test' before this script. qFALL builds GMP" >&2
        echo "       and MPFR from source, and this script then reuses that" >&2
        echo "       copy, so no developer package and no root access is" >&2
        echo "       needed. Installing libgmp-dev and libmpfr-dev also" >&2
        echo "       works if you can." >&2
        command -v cargo >/dev/null 2>&1 || {
            echo "       Cargo is not installed either. Install Rust with" >&2
            echo "       the rustup script in README.md; the cargo packaged" >&2
            echo "       by Ubuntu is too old for this crate." >&2
        }
        exit 1
    fi
    include_dir="$(dirname "$header")"
    lib_dir="$(dirname "$include_dir")/lib"
    echo "==> using the GMP and MPFR that cargo built, in $include_dir"
    CPATH="${CPATH:+$CPATH:}$include_dir"
    LIBRARY_PATH="${LIBRARY_PATH:+$LIBRARY_PATH:}$lib_dir"
    export CPATH LIBRARY_PATH
fi

if [ ! -d "$workdir/.git" ]; then
    echo "==> fetching LaZer $revision"
    mkdir -p "$workdir"
    git init --quiet "$workdir"
    git -C "$workdir" remote add origin https://github.com/lazer-crypto/lazer.git
    git -C "$workdir" fetch --depth 1 --quiet origin "$revision"
    git -C "$workdir" checkout --quiet --detach FETCH_HEAD
    git -C "$workdir" submodule update --init --recursive --quiet

    # Two bugs in the pinned revision; lazer/README.md explains both.
    echo "==> applying the upstream patches"
    for patch in "$project"/lazer/patches/*.patch; do
        patch --directory="$workdir" --strip=1 --input="$patch"
    done
fi

# Built before 'make lib-static' so the vendored HEXL configures under CMake 4,
# which no longer accepts its cmake_minimum_required. Touching the directory
# afterwards stops make from repeating the step.
if [ ! -f "$workdir/third_party/hexl-development/build/hexl/lib/libhexl.a" ]; then
    echo "==> building the vendored HEXL"
    (
        cd "$workdir/third_party"
        unzip -q -o hexl-development.zip
        cmake -S hexl-development -B hexl-development/build \
            -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF \
            -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
        cmake --build hexl-development/build -j"$(getconf _NPROCESSORS_ONLN)"
        touch hexl-development
    )
fi

echo "==> building liblazer.a"
if command -v gcc-14 >/dev/null 2>&1; then
    make -C "$workdir" CC=gcc-14 CXX=g++-14 lib-static
else
    make -C "$workdir" lib-static
fi

cat <<EOF

LaZer $revision is built. Run the LaZer-backed tests with:

  LAZER_INCLUDE_DIR=$workdir \\
  LAZER_LIB_DIR=$workdir \\
  LAZER_HEXL_LIB_DIR=$workdir/third_party/hexl-development/build/hexl/lib \\
  cargo test --features lazer-ffi -- --test-threads=1
EOF
