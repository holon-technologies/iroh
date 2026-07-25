# Changelog

## 1.1.0-holon.1

- Fork upstream `noq` 1.1.0 under the explicit `iroh-noq` package name.
- Bound endpoint and per-connection event queues by items and bytes.
- Reserve terminal delivery capacity and coalesce replaceable control state.
- Retain an opaque connection-lifetime token until the final Noq state is dropped.
- Require erased lifetime guards to preserve upstream `UnwindSafe` and
  `RefUnwindSafe` behavior for public connection, stream, and path handles.
- Add fixed-cardinality rejection diagnostics and saturation/conservation regressions.
