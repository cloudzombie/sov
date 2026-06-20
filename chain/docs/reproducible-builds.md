# Reproducible / verifiable builds (Phase 7 · p7-i7)

A sovereign reserve asset's binaries must be **verifiable**: anyone should be able
to rebuild the node from source and get the *same* bytes the network runs, so a
published binary cannot hide a backdoor. SOV's release build is deterministic by
construction and checked in CI.

## What makes the build deterministic

- **Pinned dependencies** — `Cargo.lock` is committed and builds use `--locked`,
  so the exact same dependency graph is compiled every time.
- **Deterministic codegen** — the release profile uses `codegen-units = 1`,
  `lto = "thin"`, and `panic = "abort"` (see `chain/Cargo.toml`); single-unit
  codegen removes parallelism-induced nondeterminism.
- **No embedded machine state** — the build remaps source paths
  (`--remap-path-prefix`) and fixes `SOURCE_DATE_EPOCH`, so absolute paths and
  timestamps don't leak into the artifacts.
- **Pure Rust, std-only** — no C toolchain or system libraries whose versions
  could perturb output.

## Verify it yourself

```sh
bash scripts/reproducible-build.sh
```

It builds the release binaries (`sov-node`, `sov-miner`, `sov-katgen`) twice into
separate target directories and asserts their SHA-256 hashes are identical. CI
runs this on every push (the `reproducible build` job).

## Canonical build environment

For machine-independent reproducibility, build inside the pinned container
([`chain/Dockerfile`](../Dockerfile), `FROM rust:1.93.1`), which fixes the exact
compiler, standard library, and paths:

```sh
docker build -f chain/Dockerfile -t sov-build .   # from the repo root
docker run --rm sov-build                          # prints SHA256SUMS (the attestation)
```

Two builds from the same image digest produce byte-identical binaries; that hash
list is the published attestation anyone can independently reproduce.

## Status

**Verified.** `scripts/reproducible-build.sh` produced **byte-identical**
`sov-node`, `sov-miner`, and `sov-katgen` across two clean builds (locally and via
the CI `reproducible` job). Remaining hardening for a formal release process: pin
the container base image by digest and publish signed `SHA256SUMS` with each
tagged release.
