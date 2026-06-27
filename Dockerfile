# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-backend.
FROM rust:1-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG INTERFACES_REF=main
RUN git clone --depth 1 --branch "$INTERFACES_REF" \
    https://github.com/fiducia-cloud/fiducia-interfaces.git fiducia-interfaces
COPY . fiducia-backend.rs
WORKDIR /build/fiducia-backend.rs
RUN cargo build --release && strip target/release/fiducia-backend

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && useradd --uid 10001 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin fiducia \
    && mkdir -p /app/static /app/customer-static \
    && chown -R 10001:10001 /app
COPY --from=build --chown=10001:10001 /build/fiducia-backend.rs/target/release/fiducia-backend /usr/local/bin/fiducia-backend
ENV STATIC_DIR=/app/static
ENV CUSTOMER_STATIC_DIR=/app/customer-static
EXPOSE 8080
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/fiducia-backend"]
