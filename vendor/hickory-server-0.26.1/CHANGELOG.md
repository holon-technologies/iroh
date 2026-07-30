# Changelog

## 0.26.1-holon.1

- Fork upstream `hickory-server` 0.26.1 under the explicit `krikos-hickory-server` package name.
- Add validated, nonzero UDP-request and TCP-connection admission limits.
- Acquire capacity before spawning transport tasks and conserve permits through completion,
  cancellation, and panic unwinding.
- Add fixed-cardinality admission observations and saturation/conservation regressions.
