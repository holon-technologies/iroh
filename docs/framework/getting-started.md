# Local-first application framework

`iroh-app` is an experimental, unpublished application layer that composes the fork's v2 endpoint,
blobs, gossip, and docs crates. Its package name and public API are intentionally not a semver
commitment yet.

## Standard bundle

```rust,no_run
use iroh_app::StandardBundle;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let app = StandardBundle::persistent("./my-app-data")
    .start()
    .await?;

let author = app.docs().author_default().await?;
let document = app.docs().create().await?;
document.set_bytes(author, "notes/first", "hello").await?;

app.shutdown().await?;
# Ok(())
# }
```

The default network profile uses the existing compatible relay and discovery infrastructure.
`.local_only()` disables that shared infrastructure for deterministic local applications. A private
deployment can use `.relay_map(...)` with a compatible relay map. Keep normal certificate
verification in production; the custom CA hook exists for private roots and isolated self-signed
test relays.

Startup validates the data-root manifest and obtains its exclusive lease before binding a socket.
It then resolves one protected identity, opens blobs, binds the endpoint, starts gossip and docs,
registers the three standard ALPNs plus bounded custom handlers, and publishes the running handle.
Failure rolls already-opened components back in reverse order.

The version-1 experimental data root contains:

```text
my-app-data/
├── manifest.json
├── identity.key
├── blobs/
└── docs/
```

Do not copy, rename, restore, or partially replace these files while the application is running.
Back up the entire root after clean shutdown. Existing docs redb migrations retain their documented
backup siblings; verify the migrated application before deleting those backups.

## Capabilities and custom protocols

Document invitations carry explicit read or write authority. Parse invitations as `DocTicket` and
allow its built-in size, address, and peer limits to reject untrusted input. Prefer read invitations
unless the recipient must author changes. Blob hashes are content identities: verify the downloaded
bytes against the entry hash before exposing them outside the application boundary.

Custom protocols are registered with a unique, bounded ALPN:

```rust,ignore
let app = StandardBundle::persistent("./my-app-data")
    .protocol(b"/my-company/my-protocol/1", MyHandler)?
    .start()
    .await?;
```

The standard blobs, gossip, and docs ALPNs cannot be replaced. Runtime health is available through
`app.health()`, and `app.shutdown()` is concurrent-safe, idempotent, and bounded by one absolute
deadline. Dropping the last handle triggers the same bounded cancellation path, but callers should
await explicit shutdown whenever they can report operational errors.

See [`examples/local-first-notes`](../../examples/local-first-notes/README.md) for an executable
two-node flow. The acceptance package runs that architecture directly and through a local relay,
including restart, read-capability enforcement, content verification, idempotent resync, and a
custom ALPN.

## Lower-level composition

Applications that need a different lifecycle may use `iroh-blobs`, `iroh-gossip`, or `iroh-docs`
directly. In that case the application owns endpoint construction, ALPN registration, startup
rollback, task supervision, health reporting, and bounded shutdown. It must also preserve the same
storage lease and migration rules described above. The `iroh-app` standard bundle is the supported
experimental composition for applications that do not need to own those concerns themselves.

These four packages are intentionally unpublished while their names, registry ownership, public
API baseline, and persistent-data support commitment are reviewed. The machine-readable
[`release gate`](../../framework/release-gate.toml) prevents them from entering the platform
release accidentally. When importing an upstream maintenance change, follow the
[`exact-tag provenance and compatibility runbook`](upstream-sync.md); never merge an unpinned
upstream branch into these packages.
