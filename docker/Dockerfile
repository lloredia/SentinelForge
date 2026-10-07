# syntax=docker/dockerfile:1

FROM rust:1.99.0-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp /app/target/release/sentinelforge /usr/local/bin/sentinelforge

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /usr/local/bin/sentinelforge /app/sentinelforge

ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080
USER nonroot
WORKDIR /app

ENTRYPOINT ["/app/sentinelforge"]
CMD ["--migrate"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD ["/app/sentinelforge", "--healthcheck"]
