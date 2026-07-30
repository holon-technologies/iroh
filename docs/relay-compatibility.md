# Relay V1/V2 Compatibility Contract

**Status:** normative for the v2 architecture cut.

The fork must share relay infrastructure with upstream-compatible Krikos deployments. This contract
defines wire compatibility independently from Rust source compatibility, Cargo features, operator
configuration, CLI flags, metrics, and deployment manifests.

## Pinned baseline

| Name | Git object | Commit | Role |
| --- | --- | --- | --- |
| upstream `v1.0.3` | `816dd70c056b813dcb5cbfb6a9a15e12d04b72b1` | `f2eb930dda3779c6d852b72f3712aacd6e573ab1` | sole compatibility baseline for this cut |

The baseline is immutable. A later infrastructure requirement adds another exact commit; it does
not replace `v1.0.3` and never uses a branch reference.

Baseline protocol-source SHA-256 values provide provenance for fixture generation:

| Path at `v1.0.3` | SHA-256 |
| --- | --- |
| `krikos-relay/src/http.rs` | `ea9bbf0087b35ffe6ab6c428cb86b128fd520270fa5ea17b6daab3e2f9e21793` |
| `krikos-relay/src/protos/common.rs` | `60df8d490d301b75f9fe8d51ea9839ecedc900fe7fc140a967bc014d41a1c87d` |
| `krikos-relay/src/protos/handshake.rs` | `fae68739f3cd9bc8683abb6f769298a93cea4bf53029886b4720858e1ea53913` |
| `krikos-relay/src/protos/relay.rs` | `9cc04ec4f104b4a0f89afcc4937333fb7cee5af029acad7015f9a60c26b8530f` |
| `krikos-relay/src/protos/streams.rs` | `cb426bd98b3fe1f9168f5660f39d097294715a7bada901d7dbd64d42eabc38df` |

## HTTP and negotiation constants

| Contract | Value |
| --- | --- |
| Relay path | `/relay` |
| Probe path | `/ping` |
| WebSocket upgrade protocol | `websocket` |
| Supported WebSocket version | `13` |
| Client authentication header | `x-krikos-relay-client-auth-v1` |
| Browser/query token parameter | `token` |
| Relay V1 subprotocol | `krikos-relay-v1` |
| Relay V2 subprotocol | `krikos-relay-v2` |
| Preference order | V2, then V1 |

The server chooses the highest mutually supported version. A V1-only peer must remain usable.
Unknown subprotocol values are not aliases for a known version.

## Authentication constants

| Contract | Value |
| --- | --- |
| Challenge size | 16 bytes |
| Endpoint public key | 32 bytes |
| Signature | 64 bytes |
| TLS key material | 32 bytes: sign first 16, transmit final 16 as suffix |
| Challenge signature domain | `iroh-relay handshake v1 challenge signature` |
| TLS exporter label | byte string `iroh-relay handshake v1` |
| TLS exporter context | client public-key bytes |
| Header encoding | postcard payload encoded as base64url without padding |

Changing a domain string, exporter label/context, field order, field width, or header encoding is a
wire break even if both current fork endpoints still authenticate each other.

## Frame registry

Frame tags are QUIC variable integers whose current values encode in one byte. Values are never
reused.

| Tag | Frame | Direction/version | Payload |
| ---: | --- | --- | --- |
| 0 | `ServerChallenge` | server to client, handshake | 16-byte challenge |
| 1 | `ClientAuth` | client to server, handshake | 32-byte public key + 64-byte signature |
| 2 | `ServerConfirmsAuth` | server to client, handshake | empty postcard value |
| 3 | `ServerDeniesAuth` | server to client, handshake | postcard denial reason |
| 4 | `ClientToRelayDatagram` | client to server | 32-byte endpoint + ECN byte + contents |
| 5 | `ClientToRelayDatagramBatch` | client to server | endpoint + ECN + big-endian `u16` segment size + contents |
| 6 | `RelayToClientDatagram` | server to client | 32-byte endpoint + ECN byte + contents |
| 7 | `RelayToClientDatagramBatch` | server to client | endpoint + ECN + big-endian `u16` segment size + contents |
| 8 | `EndpointGone` | server to client | 32-byte endpoint |
| 9 | `Ping` | either direction | exactly 8 opaque bytes |
| 10 | `Pong` | either direction | exactly 8 echoed bytes |
| 11 | `Health` | server to client, V1 only | UTF-8 problem text |
| 12 | `Restarting` | server to client | two big-endian `u32` millisecond durations |
| 13 | `Status` | server to client, V2+ | one status byte; 0 healthy, 1 duplicate endpoint, others unknown |

One WebSocket binary message contains one relay frame. Unknown tags, truncated fixed-width fields,
wrong-direction tags, wrong-version frames, and oversized payloads are rejected without panic.

## Bounds

| Bound | Value/behavior |
| --- | --- |
| Maximum packet contents | 64 KiB |
| Maximum WebSocket frame | 1 MiB |
| Restart duration | unsigned 32-bit milliseconds; encoding saturates at `u32::MAX` |
| Per-client send queue | 512 packets in the current implementation; changes require resource review but not wire negotiation |

The packet and frame maxima are compatibility constraints. Tightening either would reject baseline
traffic; increasing either without bounded allocation review would weaken resource safety.

## Required interoperability matrix

| Client | Server | Required versions |
| --- | --- | --- |
| current fork | upstream `v1.0.3` | forced V1, forced V2, normal negotiation |
| upstream `v1.0.3` | current fork | forced V1, forced V2, normal negotiation |
| current fork | current fork | forced V1, forced V2, normal negotiation |

Each direction covers connection/authentication, bidirectional single and batched datagrams,
ping/pong, endpoint-gone, restart, and the version-appropriate V1 health or V2 status frame. Header
authentication, query-token authentication, and challenge fallback are covered where supported by
the transport. Extensions absent from the baseline are capability-scoped and are not described as
baseline-compatible.

Golden codec and transcript fixtures run on every pull request. Process-level baseline/current
interoperability runs in scheduled and release CI with pinned source, lockfile, toolchain/container,
bounded ports/processes/timeouts, and retained revision-stamped logs. Build/infrastructure failure
and incompatibility are reported separately, but neither may silently pass.

## Change rules

- Do not update a golden fixture merely because current output changed; explain the difference and
  prove it is compatible first.
- Do not repurpose V1/V2 tags, authentication material, or serialization.
- A new wire behavior uses a new additive `ProtocolVersion` and negotiates with older peers.
- A new version does not remove V1/V2 tests while either remains in the compatibility SLA.
- Relay server/client module refactors run the golden gate after each move and the live matrix after
  any upgrade, authentication, codec, or session change.
- A compatibility failure blocks the release independently of Rust semver policy.
