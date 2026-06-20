# syntax=docker/dockerfile:1
#
# Canonical reproducible build environment for SOV (Phase 7 · p7-i7).
#
# Pins the EXACT Rust toolchain (1.93.1) and applies the same determinism
# settings as scripts/reproducible-build.sh. Anyone building from this image gets
# byte-for-byte identical binaries, so a published release can be independently
# reproduced and verified — a backdoor cannot hide in the binary.
#
# Build from the repo root:
#   docker build -f chain/Dockerfile -t sov-build .
#   docker run --rm sov-build cat /build/SHA256SUMS   # the attestation
#
# Reproduce: build twice (same image digest) and diff the SHA256SUMS.
FROM rust:1.93.1-slim

# Determinism: a fixed source date; the image fixes all paths and tool versions.
ENV SOURCE_DATE_EPOCH=1700000000 \
    CARGO_TERM_COLOR=never

WORKDIR /build
COPY chain ./chain
WORKDIR /build/chain

# Build the shipped binaries with the locked dependency graph, then record the
# SHA-256 of each — that hash list IS the build attestation.
RUN cargo build --release --locked -p sov-node -p sov-rpc \
 && sha256sum \
      target/release/sov-node \
      target/release/sov-miner \
      target/release/sov-katgen \
    | sed 's#target/release/##' | tee /build/SHA256SUMS

CMD ["cat", "/build/SHA256SUMS"]
