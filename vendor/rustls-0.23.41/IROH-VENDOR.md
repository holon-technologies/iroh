# Vendored rustls 0.23.41

## Upstream

`rustls` 0.23.41, exactly as published on crates.io, normalized with
`rustfmt --edition 2021` at default settings.

## Why this fork exists

`iroh-sim` requires deterministic, run-scoped cryptography so that a simulation
replays identically from a seed. Upstream rustls draws session identifiers and
`Random` values from an ambient source and does not expose which key-exchange
group a connection negotiated, both of which make replay impossible.

## Why a patch, not a wrapper

Rustls 0.23's public `CryptoProvider` stores `secure_random: &'static dyn SecureRandom` and
`kx_groups: Vec<&'static dyn SupportedKxGroup>`. A provider whose entropy and X25519 state are
owned by one simulation run cannot be built through the public API, because that API requires
`'static` references: it would have to leak run state to obtain `'static`, dispatch through
process-global or thread-local state, or use a forked provider API. The first two were rejected —
they violate `iroh-sim`'s run-scoping and no-leak invariants (a leaked or globally dispatched
provider would couple concurrent simulation workers and make cleanup between runs unsound). A
fourth alternative, dropping raw ciphertext replay and keeping only the production-crypto
semantic-parity lane, was also rejected because it would remove an already-established
byte-exact replay guarantee. The chosen approach — this narrow fork, whose provider owns
`secure_random` and `kx_groups` through `Arc` instead of `&'static` — is therefore the only option
that keeps both lanes (byte-exact deterministic replay and production-crypto semantic parity;
see [`docs/testing/determinism-audit.md`](../../docs/testing/determinism-audit.md)) without leaking
state or introducing global mutable dispatch.

## The patch

`vendor/rustls-0.23.41.patch`, roughly 529 lines across 12 files:

- `KxState` holds `Arc<dyn SupportedKxGroup>` rather than a borrowed reference,
  so the negotiated group outlives the handshake.
- A public `negotiated_key_exchange_group()` accessor on the connection.
- `provider.secure_random` is threaded through session-ID and `Random`
  construction instead of an ambient source.

Files: `src/common_state.rs`, `src/crypto/mod.rs`, `src/crypto/aws_lc_rs/mod.rs`,
`src/crypto/ring/mod.rs`, `src/client/{hs,tls12,tls13,ech,client_conn}.rs`,
`src/server/{hs,tls12,tls13}.rs`.

## Scope

Simulator only. This crate is patched in by `iroh-sim/Cargo.toml`. No
production crate resolves it — production uses rustls from crates.io. See
[`docs/architecture.md`](../../docs/architecture.md#vendored-dependency-boundary)
for why a renamed rustls fork is not viable.

## Update procedure

1. Download the new upstream package from crates.io.
2. Normalize it: `find . -name '*.rs' -print0 | xargs -0 -n1 rustfmt --edition 2021`.
3. Apply `vendor/rustls-0.23.41.patch`, resolving conflicts by hand.
4. Rename the directory and patch file to the new version and update
   `iroh-sim/Cargo.toml`.
5. Run `scripts/tests/check-vendor-provenance.sh`.

## Why this cannot simply be removed

Deleting the patch removes deterministic replay from every simulation, which
is the property the simulator exists to provide.
