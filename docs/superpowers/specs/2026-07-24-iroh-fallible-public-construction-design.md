# RFC: Make Fallible Public Construction Explicit

## Status

Approved by the user on 2026-07-24; implemented on 2026-07-24.

## Scope

This RFC removes the remaining production `expect` calls that can be reached with caller-supplied
configuration:

- `iroh_dns::dns::Builder::build`;
- `iroh::address_lookup::PkarrRelayClientBuilder::build`;
- native and browser `iroh::address_lookup::PkarrRelayClient::new`;
- `iroh::address_lookup::PkarrPublisherBuilder::build`;
- `iroh::address_lookup::PkarrResolverBuilder::build`; and
- `iroh_relay::quic::QuicClient::new`.

It does not convert test assertions, process-wide mutex-poison invariants, fixed-size conversion
proofs, or child-task panic propagation into recoverable errors.

## Confirmed Failure Boundaries

### DNS resolver

`iroh_dns::dns::Builder::build() -> DnsResolver` calls Hickory's fallible
`ResolverBuilder::build() -> Result<_, hickory_resolver::net::NetError>` and currently asserts
success with `expect("config works")`. A caller can provide a custom TLS client configuration, so
the construction input is not entirely controlled by Iroh.

### Pkarr HTTP client

`PkarrRelayClientBuilder::build` and both target-specific `PkarrRelayClient::new` variants call
`reqwest::ClientBuilder::build().expect(...)`. The publisher and resolver builders delegate to
these constructors, so their signatures must carry the same failure.

### Relay QUIC address-discovery client

`QuicClient::new` accepts an arbitrary `rustls::ClientConfig` and calls
`QuicClientConfig::try_from(...).expect("known ciphersuite")`. A configuration whose crypto
provider lacks TLS 1.3 AES-128-GCM-SHA256 returns `NoInitialCipherSuite` and currently panics.

## Options

### Option A: Add `try_*` APIs and retain the panicking APIs

Add fallible alternatives, deprecate the current methods, and leave the current methods as
wrappers that panic on error.

This minimizes immediate source breakage, but production public entry points remain capable of
panicking. It therefore does not satisfy the requested TigerStyle end state.

### Option B: Store construction failure and report it during first use

Preserve the constructors by storing an error-backed object that fails every later operation.

This delays a deterministic configuration failure, complicates every object's state, and makes
startup appear successful when the object is unusable. It is not recommended.

### Option C: Make every affected constructor fallible

Change the affected methods to return typed `Result` values and propagate the failures through
existing fallible endpoint/server construction.

This is a source-breaking API change, but it makes the configuration boundary explicit, preserves
the original error, and removes the reachable panics completely.

## Recommendation

Choose Option C.

Full TigerStyle adherence is incompatible with retaining public methods that panic for invalid
caller-supplied configuration. A coordinated change is clearer than introducing a mixture of
deprecated panicking wrappers and new fallible methods.

## API Design

### DNS

- Add a non-exhaustive public `BuildError` carrying
  `hickory_resolver::net::NetError`.
- Change `Builder::build(self) -> Result<DnsResolver, BuildError>`.
- Make `HickoryResolver::new` and `build_resolver` fallible.
- Keep `DnsResolver::new()` and `Default` infallible because their fixed internal configuration is
  proven at construction; use a private invariant helper for that controlled path.
- Update all custom-builder call sites to use `?` or an explicitly documented invariant.

### Pkarr

- Add `PkarrError::HttpClient` carrying the `reqwest::Error`.
- Change `PkarrRelayClientBuilder::build` and `PkarrRelayClient::new` to return
  `Result<_, PkarrError>`.
- Change `PkarrPublisherBuilder::build` and `PkarrResolverBuilder::build` to return
  `Result<_, PkarrError>`.
- Make the private `PkarrPublisher::new` fallible.
- Map `PkarrError` into `AddressLookupBuilderError::from_err("pkarr", error)` in the existing
  fallible `AddressLookupBuilder::into_address_lookup` path.
- Propagate errors through examples, benches, tests, and DNS-server construction.

### Relay QAD

- Add a non-exhaustive public `QuicClientBuildError` containing
  `noq::crypto::rustls::NoInitialCipherSuite`.
- Change `QuicClient::new` to return `Result<QuicClient, QuicClientBuildError>`.
- Make `net_report::Client::new` fallible and propagate through endpoint binding, which is already
  fallible.
- Update relay tests and direct QAD callers to use `?`.

## Compatibility

- Wire protocols, persisted state, normal runtime behavior, and valid configuration are unchanged.
- Source compatibility changes wherever callers use the affected constructors.
- The change should be called out in release notes and migration guidance with before/after
  examples showing the added `?`.
- No compatibility wrapper may call `unwrap`, `expect`, or `panic` on caller-controlled input.

## Verification

1. Add a DNS builder test using an invalid TLS configuration and assert a typed build error.
2. Add native and browser pkarr builder tests that inject a reqwest build failure where the target
   supports doing so; otherwise test the shared error-mapping helper directly and retain reqwest's
   error as the source.
3. Add a QAD test using a Rustls provider without the required initial QUIC cipher suite and assert
   `QuicClientBuildError`.
4. Update all first-party call sites without compatibility panics.
5. Run native and Wasm compile checks, strict workspace Clippy, workspace tests, and the panic-lint
   audit.
6. Confirm no production warning remains for the replaced `expect` sites.

## Approval

The user approved Option C on 2026-07-24, accepting the coordinated source-breaking API change.
