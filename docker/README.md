# Krikos Docker Images

## Intro

A set of docker images provided to easily run krikos in a containerized environment.
Features `krikos-relay` and `krikos-dns-server`.

The provided `Docker` files are intended for CI use but can be also manually built.

## Building

- All commands are run from the root folder
- If you're on macOS run `docker buildx build -f docker/Dockerfile --target krikos-relay --platform linux/arm64/v8 --tag n0computer/krikos-relay:latest .`
- If you're on linux run `docker buildx build -f docker/Dockerfile --target krikos-relay --platform linux/amd64 --tag n0computer/krikos-relay:latest .`
- Switch out `--target krikos-relay` for `krikos-dns-server`

## Running

### krikos-relay

- Provide a config file: `docker run -v /path/to/krikos-relay.conf:/config/krikos-relay.conf -p 80:80 -p 443:443 -p 3478:3478/udp -p 9090:9090 -it n0computer/krikos-relay:latest <params> --config /config/krikos-relay.conf`

### krikos-dns-server

- Provide a config file: `docker run -v /path/to/krikos-dns-server.conf:/config/krikos-dns-server.conf -p 53:53/udp -p 9090:9090 -it n0computer/krikos-dns-server:latest <params> --config /config/krikos-dns-server.conf`

## Development test environment

On Linux hosts where unprivileged user namespaces are restricted, use the
project-owned test environment:

```bash
scripts/krikos-test-env
```

With no arguments, it runs the full all-feature workspace test suite. Patchbay
tests run sequentially because each case creates a complete network lab.
Arbitrary commands can be supplied instead:

```bash
scripts/krikos-test-env \
  cargo test -p krikos --all-features --test patchbay \
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

Set `KRIKOS_TEST_BUILD_JOBS` to change build parallelism. `KRIKOS_TEST_IMAGE`,
`KRIKOS_REPO_ROOT`, `KRIKOS_TEST_DOCKERFILE`, and `KRIKOS_TEST_ENTRYPOINT` are
available for advanced overrides.
