# Iroh Docker Images

## Intro

A set of docker images provided to easily run iroh in a containerized environment.
Features `iroh-relay` and `iroh-dns-server`.

The provided `Docker` files are intended for CI use but can be also manually built.

## Building

- All commands are run from the root folder
- If you're on macOS run `docker buildx build -f docker/Dockerfile --target iroh-relay --platform linux/arm64/v8 --tag n0computer/iroh-relay:latest .`
- If you're on linux run `docker buildx build -f docker/Dockerfile --target iroh-relay --platform linux/amd64 --tag n0computer/iroh-relay:latest .`
- Switch out `--target iroh-relay` for `iroh-dns-server`

## Running

### iroh-relay

- Provide a config file: `docker run -v /path/to/iroh-relay.conf:/config/iroh-relay.conf -p 80:80 -p 443:443 -p 3478:3478/udp -p 9090:9090 -it n0computer/iroh-relay:latest <params> --config /config/iroh-relay.conf`

### iroh-dns-server

- Provide a config file: `docker run -v /path/to/iroh-dns-server.conf:/config/iroh-dns-server.conf -p 53:53/udp -p 9090:9090 -it n0computer/iroh-dns-server:latest <params> --config /config/iroh-dns-server.conf`

## Development test environment

On Linux hosts where unprivileged user namespaces are restricted, use the
project-owned test environment:

```bash
scripts/iroh-test-env
```

With no arguments, it runs the full all-feature workspace test suite. Patchbay
tests run sequentially because each case creates a complete network lab.
Arbitrary commands can be supplied instead:

```bash
scripts/iroh-test-env \
  cargo test -p iroh --all-features --test patchbay \
  holepunch_simple -- --exact
```

The runner:

- builds `docker/Dockerfile.test-env` on first use;
- runs privileged and AppArmor-unconfined so Patchbay can create user and
  network namespaces and use `tc` and `nft`;
- mounts the checkout read-only beneath a temporary copy-on-write overlay, so
  tests can create in-worktree artifacts without changing host files;
- persists Cargo registry, Git, and target caches in named Docker volumes; and
- defaults to two Cargo build jobs to avoid memory pressure.

Set `IROH_TEST_BUILD_JOBS` to change build parallelism. `IROH_TEST_IMAGE`,
`IROH_REPO_ROOT`, `IROH_TEST_DOCKERFILE`, and `IROH_TEST_ENTRYPOINT` are
available for advanced overrides.
