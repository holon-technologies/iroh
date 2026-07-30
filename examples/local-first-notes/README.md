# Local-first notes

This executable demonstrates the standard unpublished `krikos-app` bundle using only public
framework and protocol APIs. It starts two persisted nodes, routes a custom bounded echo ALPN,
adds note bytes to the blob store, references the hash from a read-shared document, waits for the
second node to validate and download the content, rejects an unauthorized write, shuts down, and
reopens the first node to prove durability.

```console
cargo run -p local-first-notes -- /tmp/krikos-notes-demo "my first note"
```

The directory contains separate `node-a` and `node-b` roots. Each root owns `manifest.json`, a
protected endpoint identity, blob data, and document state. Stop the program cleanly before moving,
backing up, or restoring either root.

The example uses local direct addresses so it is deterministic. Applications that want the shared
compatible infrastructure should omit `.local_only()`. Private deployments can supply a compatible
`RelayMap` with `.relay_map(...)`; only isolated tests with self-signed relay certificates should
override TLS CA verification.
