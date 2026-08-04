# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG RUST_BUILD_IMAGE=rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
ARG DEBIAN_RUNTIME_IMAGE=debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_BUILD_IMAGE} AS builder
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --locked -p buzz-core-worker --bin buzz-core-worker \
    && strip target/release/buzz-core-worker

FROM ${DEBIAN_RUNTIME_IMAGE} AS runtime
LABEL org.opencontainers.image.title="Core Buzz Month-1 workers" \
      org.opencontainers.image.source="https://github.com/block/buzz" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 buzz \
    && useradd --system --uid 1000 --gid 1000 --home-dir /var/lib/buzz \
       --create-home --shell /usr/sbin/nologin buzz
COPY --from=builder /build/target/release/buzz-core-worker /usr/local/bin/buzz-core-worker
USER buzz:buzz
WORKDIR /var/lib/buzz
ENTRYPOINT ["/usr/local/bin/buzz-core-worker"]
