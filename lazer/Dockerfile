# syntax=docker/dockerfile:1
# Report: "LaZer Integration Feasibility".

ARG LAZER_PLATFORM=linux/amd64
ARG SAGE_IMAGE=docker.io/sagemath/sagemath:10.2@sha256:a7c4f3d0536aa1e93c106ac31ea2ae035299f9afcfdcb4a549c396374fb926a9

FROM --platform=${LAZER_PLATFORM} ubuntu:24.04 AS build

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
       ca-certificates cmake g++-14 gcc-14 git libgmp-dev libmpfr-dev \
       make patch unzip \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=bind,source=lazer/LAZER_REVISION,target=/tmp/LAZER_REVISION \
    revision="$(cat /tmp/LAZER_REVISION)" \
    && git init /src/lazer \
    && git -C /src/lazer remote add origin https://github.com/lazer-crypto/lazer.git \
    && git -C /src/lazer fetch --depth 1 origin "$revision" \
    && git -C /src/lazer checkout --detach FETCH_HEAD \
    && git -C /src/lazer submodule update --init --recursive

COPY lazer/patches/0001-pass-input-equations-to-tbox.patch /tmp/lazer.patch
RUN patch --directory=/src/lazer --strip=1 --input=/tmp/lazer.patch

WORKDIR /src/lazer

RUN make CC=gcc-14 CXX=g++-14 lib-static

FROM --platform=${LAZER_PLATFORM} ${SAGE_IMAGE} AS parameter-generator

COPY --chown=sage:sage --from=build /src/lazer/scripts /src/lazer/scripts
COPY --chown=sage:sage --from=build /src/lazer/third_party/estimator.py /src/lazer/third_party/estimator.py

WORKDIR /src/lazer/scripts

ENTRYPOINT ["sage"]

FROM --platform=${LAZER_PLATFORM} rust:1.93-bookworm AS rust-runner

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
       g++ libgmp-dev libmpfr-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/lazer/lazer.h /opt/lazer/include/lazer.h
COPY --from=build /src/lazer/src/moduli.h /opt/lazer/include/src/moduli.h
COPY --from=build /src/lazer/liblazer.a /opt/lazer/lib/liblazer.a
COPY --from=build /src/lazer/third_party/hexl-development/build/hexl/lib/libhexl.a /opt/lazer/lib/libhexl.a

ENV CARGO_TARGET_DIR=/cargo-target \
    LAZER_INCLUDE_DIR=/opt/lazer/include \
    LAZER_LIB_DIR=/opt/lazer/lib \
    LAZER_HEXL_LIB_DIR=/opt/lazer/lib \
    CC=gcc \
    CXX=g++ \
    CFLAGS="" \
    CXXFLAGS="" \
    LIBRARY_PATH=/opt/lazer/lib

WORKDIR /project

CMD ["cargo", "test", "--features", "lazer-ffi", "--config", "build.target=\"x86_64-unknown-linux-gnu\"", "--", "--test-threads=1"]

FROM scratch AS library-artifacts

COPY --from=build /src/lazer/lazer.h /include/lazer.h
COPY --from=build /src/lazer/src/moduli.h /include/src/moduli.h
COPY --from=build /src/lazer/liblazer.a /lib/liblazer.a
COPY --from=build /src/lazer/third_party/hexl-development/build/hexl/lib/libhexl.a /lib/libhexl.a
COPY lazer/LAZER_REVISION /metadata/LAZER_REVISION
