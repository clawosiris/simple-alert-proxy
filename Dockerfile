FROM rust:1-bookworm AS build

WORKDIR /app
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/simple-alert-proxy simple-alert-proxy

COPY --from=build /app/target/release/simple-alert-proxy /usr/local/bin/simple-alert-proxy

USER simple-alert-proxy
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/simple-alert-proxy"]
CMD ["--config", "/etc/simple-alert-proxy/config.yaml"]
