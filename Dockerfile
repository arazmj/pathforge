# syntax=docker/dockerfile:1
FROM rust:1.85-slim as builder

# Install nightly toolchain (required for indexmap edition2024)
RUN rustup toolchain install nightly && rustup default nightly

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
# Build deps layer (cache-friendly)
RUN mkdir src && echo 'fn main(){}' > src/main.rs && \
    cargo build --release 2>/dev/null || true && rm -rf src

COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/pathforge /usr/local/bin/pathforge
EXPOSE 179
ENTRYPOINT ["pathforge"]
