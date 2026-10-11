FROM rust:1-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --release --locked -p entangle

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 entangle \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /var/lib/entangle --shell /usr/sbin/nologin entangle

COPY --from=builder /src/target/release/entangle /usr/local/bin/entangle

LABEL org.opencontainers.image.source="https://github.com/DailenG/entangle" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENV HOME=/var/lib/entangle
WORKDIR /var/lib/entangle
VOLUME /var/lib/entangle
EXPOSE 7338
USER entangle
ENTRYPOINT ["/usr/local/bin/entangle"]
CMD ["repeater", "serve", "--listen", "0.0.0.0:7338"]
