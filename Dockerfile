FROM rust:1-bookworm AS build

WORKDIR /app
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /var/lib/signoz-alert-proxy signoz-alert-proxy

COPY --from=build /app/target/release/signoz-alert-proxy /usr/local/bin/signoz-alert-proxy

USER signoz-alert-proxy
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/signoz-alert-proxy"]
CMD ["--config", "/etc/signoz-alert-proxy/config.yaml"]
