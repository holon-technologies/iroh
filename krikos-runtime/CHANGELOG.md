# Changelog

All notable changes to iroh-runtime will be documented in this file.

## Unreleased

### Features

- Added explicit clock, wall-clock, executor, task-group, decision-source, ID,
  and trace capabilities shared by production Iroh and deterministic
  simulation.
- Added finite task-group admission and structured task outcomes.
- Added deterministic decision streams and a versioned causal trace schema.
- Added typed clock-resource admission failures for timers and scheduled events.

### Compatibility

- This is the first published release of `iroh-runtime`. It is an
  implementation dependency of `iroh` and `iroh-relay`; applications do not
  need to depend on it unless they provide runtime or simulation integrations.
