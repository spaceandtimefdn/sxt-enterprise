# syntax=docker/dockerfile:1
FROM rust:1.90-slim-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo build --release

# Pre-warm the setup cache so first boot needs no download. Override --rows to match the
# capacity the deployed `serve --rows` will ask for.
FROM build AS setup
ARG ROWS=1024
RUN ./target/release/sxt-enterprise setup --rows ${ROWS} --out /setup.bin

FROM debian:bookworm-slim
RUN useradd --system --create-home --home-dir /data sxt-enterprise
COPY --from=build /build/target/release/sxt-enterprise /usr/local/bin/sxt-enterprise
COPY --from=setup /setup.bin /data/setup.bin
USER sxt-enterprise
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["sxt-enterprise", "serve", "--data", "/data", "--listen", "0.0.0.0:8080"]
CMD ["--rows", "1024"]
