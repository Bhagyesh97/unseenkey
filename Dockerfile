# Builds `usk` from this source tree and starts its MCP server on stdio.
#
# This file is for MCP directories (Glama and others) that start a server in a
# container to read its tool list. It is not how Unseenkey is meant to be run:
# the vault and the broker belong on your own machine (see README.md, Install).
# With no vault in the container the server still answers `initialize` and
# `tools/list`; a tool call answers that nothing is set up here.
#
#   docker build -t unseenkey-mcp .
#   docker run -i --rm unseenkey-mcp

FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl build-essential \
 && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable
# RUSTUP_TOOLCHAIN stops rustup fetching what rust-toolchain.toml lists for
# development (clippy, rustfmt, the wasm target); the build needs none of it.
ENV PATH=/root/.cargo/bin:$PATH RUSTUP_TOOLCHAIN=stable
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release --locked -p usk

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home usk
COPY --from=build /src/target/release/usk /usr/local/bin/usk
USER usk
ENTRYPOINT ["usk", "mcp", "--client", "docker"]
