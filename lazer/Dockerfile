# syntax=docker/dockerfile:1
# Report: "LaZer Integration Feasibility".

FROM --platform=linux/amd64 ubuntu:24.04 AS build

RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
       ca-certificates cmake g++-14 gcc-14 git libgmp-dev libmpfr-dev \
       make patch unzip \
    && rm -rf /var/lib/apt/lists/*

RUN git init /src/lazer \
    && git -C /src/lazer remote add origin https://github.com/lazer-crypto/lazer.git \
    && git -C /src/lazer fetch --depth 1 origin 2fa3dfb1de7cf5d7f70ed34dd101d8863c624cfe \
    && git -C /src/lazer checkout --detach FETCH_HEAD \
    && git -C /src/lazer submodule update --init --recursive

WORKDIR /src/lazer

RUN make CC=gcc-14 CXX=g++-14 lib-static

FROM scratch AS library-artifacts

COPY --from=build /src/lazer/lazer.h /include/lazer.h
COPY --from=build /src/lazer/liblazer.a /lib/liblazer.a
COPY --from=build /src/lazer/third_party/hexl-development/build/hexl/lib/libhexl.a /lib/libhexl.a
COPY lazer/LAZER_REVISION /metadata/LAZER_REVISION
