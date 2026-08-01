# ADR-0003: Keep n0-operated relay and discovery endpoints as the shipped defaults

## Status

Accepted on 2026-07-31. The project owner weighed operating Holon-owned infrastructure against
retaining the inherited endpoints and chose to retain them, with the dependency disclosed.

This records a decision that was previously an unexamined inheritance. The endpoints were never
deliberately chosen — they arrived with the fork from `n0-computer/iroh` and were carried forward.
As of this ADR they are a choice.

## Scope

This covers which relay, DNS-discovery, and pkarr-publishing endpoints Krikos contacts by default,
and how that is disclosed to users.

It does not change any code, constant, preset, or default. It does not commit to operating
infrastructure, and it does not preclude revisiting the decision.

## Context

Krikos contacts three separable n0-operated services by default, via the `N0` preset:

| Service | Endpoint | Purpose | Consequence if unavailable |
|---|---|---|---|
| Relay fallback | `use1-1`, `usw1-1`, `euc1-1`, `aps1-1` `.relay.n0.iroh.link` | Carries traffic when hole-punching fails | Peers behind hard NATs cannot connect |
| DNS discovery | `dns.iroh.link` | Resolves endpoint IDs to addresses | **Dialing by public key stops working** — the product's headline capability |
| Pkarr publishing | `https://dns.iroh.link/pkarr` | Where an endpoint publishes its own record | Peers cannot be discovered |

These are defined in `krikos/src/defaults.rs`, `krikos-dns/src/dns.rs`, and
`krikos/src/address_lookup/pkarr.rs`. The `N0` preset is what `krikos/examples/echo.rs` and the
README quickstart use, so it is what a new user gets.

CI additionally sets `KRIKOS_FORCE_STAGING_RELAYS=1`, pointing test runs at n0's *staging* relays
(`ci.yml`, `tests.yaml`).

### What this repository already ships

Independence would not require new engineering. The repository contains deployable implementations
of every one of these services:

- `krikos-relay` — a relay server binary with built-in Let's Encrypt support (`CertMode::LetsEncrypt`).
- `krikos-dns-server` — serves both `/dns-query` (DNS-over-HTTPS discovery) and `/pkarr/{key}`
  (publish and resolve), with a `config.prod.toml` in-tree.
- CI already publishes container images to `ghcr.io/holon-technologies/krikos-relay` and
  `ghcr.io/holon-technologies/krikos-dns-server`.
- A neutral `Minimal` preset exists that configures only a crypto provider and contacts nothing.

The blocker is operational, not technical: hosting across regions, TLS renewal, uptime, abuse
handling, and — because relays carry other parties' traffic by design — an open-ended bandwidth
bill.

## Decision

**Keep the n0-operated endpoints as the shipped defaults, and disclose the dependency plainly.**

The root `README.md` names the specific hostnames in its "Relationship to upstream" section, states
that these are inherited from upstream rather than operated by Krikos, cites
`krikos/src/defaults.rs`, and shows how to substitute a different relay via
`Builder::relay_mode(RelayMode::Custom(...))`.

## Alternatives rejected

- **Operate Holon-owned endpoints.** Genuine independence, and the code to do it already ships.
  Rejected for now on operating cost: matching n0's four-region coverage means hosting, certificate
  management, on-call, and unbounded relay bandwidth, for a project that has not yet published a
  crate.
- **Ship `Minimal` as the default and require explicit endpoint configuration.** Removes any silent
  third-party dependency without operating anything. Rejected because it moves the burden to every
  consumer and removes the works-out-of-the-box behaviour that makes dialing by public key
  compelling.

## Consequences

### Accepted risks

- Krikos's headline capability — dialing by public key — depends on a service operated by another
  organisation, with no service-level agreement and no obligation to this project.
- n0 may rotate hostnames, restrict access, or withdraw the service. Every deployed Krikos endpoint
  using the default preset would be affected simultaneously.
- Default-configured Krikos deployments send relay traffic to n0 at n0's expense. This is an
  uncosted transfer from a project marketed independently.
- CI can be reddened by an outage in n0's staging infrastructure. This has already happened: an
  Android job failed with `ConnectError::Connect` and passed on rerun. Such failures present as
  defects in this repository until disproven.

### Mitigations in place

- The dependency is disclosed by name in the README, so no user adopts it unknowingly.
- `RelayMode::Custom` and the `Minimal` preset let any consumer opt out without forking.
- The test suite no longer contributes load. This took three passes, each of which fixed what it
  looked at and left the rest. The first made hermetic the tests that *blocked* on a relay
  handshake. The second caught eight `krikos-blobs` tests that merely *configured* n0's endpoints
  without blocking — fast and green, so they hid; one opened 17 connections to all four n0 relay
  regions and `dns.iroh.link`. The third caught twelve `krikos` endpoint tests whose own comments
  said "without Address Lookup" while `presets::N0` attached a pkarr publisher regardless.

  Measured by syscall trace rather than inspection: the `krikos` suite went from 32 external
  connections to 20, and all 20 belong to one test. Excluding it, the other 153 tests open zero
  connections beyond loopback.

  What remains is deliberate: `simple_endpoint_id_based_connection_transfer` dials by endpoint ID,
  which requires a real publish/resolve round trip against n0 staging. It is the end-to-end proof
  of the headline capability, so it keeps its dependency and is the sole documented exemption.

- `scripts/tests/check-hermetic-tests.sh` (CI) fails any test file that uses `presets::N0` or
  `RelayMode::Default` outside that exemption. Three separate fixes were needed because nothing
  checked; this is the check. It also fails on an unused exemption, so the allowed set cannot widen
  by neglect.

### Revisiting

Reconsider if any of the following becomes true: a crate release makes the user base large enough
that the bandwidth transfer is material; n0 signals a change to these services; an outage causes
user-visible breakage; or the project acquires infrastructure for other reasons. Because
`krikos-relay` and `krikos-dns-server` ship here, the decision can be reversed by deployment and a
constant change, without engineering work.
