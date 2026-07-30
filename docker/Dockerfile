FROM rust:alpine AS chef

RUN update-ca-certificates
RUN apk add --no-cache musl-dev openssl-dev pkgconfig
RUN cargo install cargo-chef
WORKDIR /krikos

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

### Builder image
FROM chef AS rust_builder

RUN update-ca-certificates
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

COPY --from=planner /krikos/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

WORKDIR /krikos

# copy entire workspace
COPY . .

RUN cargo build --release --all-features

### Target image
FROM alpine:latest AS krikos-relay

RUN apk update && apk add ca-certificates && update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /krikos/target/release/krikos-relay /krikos-relay

RUN chmod +x /krikos-relay

WORKDIR /

# expose the default ports
# http, https, metrics
EXPOSE  80 443 3478/udp 9090
ENTRYPOINT ["/krikos-relay"]
CMD [""]

### Target image
FROM alpine:latest AS krikos-dns-server

RUN apk update && apk add ca-certificates && update-ca-certificates

# Copy our build, changing owndership to distroless-provided "nonroot" user,
# (65532:65532)
COPY --from=rust_builder /krikos/target/release/krikos-dns-server /krikos-dns-server

RUN chmod +x /krikos-dns-server

WORKDIR /

# expose the default ports
# dns, metrics
EXPOSE 53/udp 9090
ENTRYPOINT ["/krikos-dns-server"]
CMD [""]
