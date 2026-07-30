# Changelog

All notable changes to krikos-runtime will be documented in this file.

## Unreleased

### Features

- Added explicit clock, wall-clock, executor, task-group, decision-source, ID,
  and trace capabilities shared by production Krikos and deterministic
  simulation.
- Added finite task-group admission and structured task outcomes.
- Added deterministic decision streams and a versioned causal trace schema.
- Added typed clock-resource admission failures for timers and scheduled events.

### Compatibility

- This is the first published release of `krikos-runtime`. It is an
  implementation dependency of `krikos` and `krikos-relay`; applications do not
  need to depend on it unless they provide runtime or simulation integrations.
