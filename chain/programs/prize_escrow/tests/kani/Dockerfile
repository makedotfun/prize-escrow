# Kani (model-checking/kani, Apache-2.0 OR MIT) for the prize_escrow proofs in this directory. The
# host never gets this toolchain (.cosmos/rules/host-runtime.mdc): cargo-kani, the nightly it pins
# (nightly-2026-08-21 for 0.68.0) and its CBMC bundle live in this image only. run.mjs builds it
# and runs every harness in it.
#
# rust:1.89.0 (the program's toolchain, chain/rust-toolchain.toml) only builds the cargo-kani
# launcher; `cargo kani setup` downloads Kani's release bundle from GitHub and installs its own
# nightly through rustup, which every proof compiles with. Trixie, not bookworm: the 0.68.0
# bundle's binaries need glibc 2.39 (bookworm has 2.36).
FROM rust:1.89.0-trixie@sha256:57407b378b2b6e07b48a6135a20c87cc22ea6e249c0acf6cb1833ead3cf116e9

ARG KANI_VERSION=0.68.0
RUN cargo install --locked kani-verifier --version "${KANI_VERSION}" \
    && cargo kani setup \
    && cargo kani --version

# chain/rust-toolchain.toml names these components; `cargo kani` under chain/ goes through that
# toolchain's cargo first, and rustup would otherwise fetch them on every run.
RUN rustup component add --toolchain 1.89.0 clippy rustfmt

WORKDIR /src
