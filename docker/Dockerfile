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

# cargo chef's recipe only embeds manifests for workspace *members* (see
# `cargo chef prepare`'s output). The [patch.crates-io] targets in the root
# Cargo.toml (vendor/hickory-server-0.26.1, vendor/noq-1.1.0) are
# deliberately excluded from the workspace -- they're vendored forks, not
# our own crates -- so they never made it into recipe.json. Cargo still
# reads their Cargo.toml (and compiles their real source) directly off disk
# during dependency resolution, so `cook` needs them present. Copy just
# those two directories, not the whole tree: this keeps them a distinct,
# independently-cached layer that only invalidates when a vendored patch
# actually changes, instead of collapsing into the full workspace COPY
# below (which invalidates on every source edit and would defeat the
# caching this stage exists for).
COPY vendor/hickory-server-0.26.1 vendor/hickory-server-0.26.1
COPY vendor/noq-1.1.0 vendor/noq-1.1.0

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
