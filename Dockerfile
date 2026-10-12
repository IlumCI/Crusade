# Crusade — multi-stage build. Produces a small runtime image with the nmap
# service-probes file (required for fingerprinting) and CA certificates.
FROM rust:1-slim AS build
WORKDIR /src
# Cache deps first.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
RUN cargo build --release --locked

FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /crusade
COPY --from=build /src/target/release/crusade /usr/local/bin/crusade
# Config + data are mounted at runtime (see docker-compose.yml).
EXPOSE 8088
ENTRYPOINT ["crusade"]
CMD ["serve", "--bind", "0.0.0.0:8088"]
