# Changelog

All notable changes to krikos-resolver will be documented in this file.

## Unreleased

### Features

- Extracted generic A, AAAA, TXT, and host resolution from `krikos-dns`.
- Added explicit Ring and AWS-LC provider features for encrypted DNS transports.
- Preserved deterministic timeout, stagger, cache clearing, and atomic reset capabilities.

### Compatibility

- This is the first published release of `krikos-resolver`.
- Endpoint-record lookup now composes this crate through `krikos-dns::dns::EndpointDnsResolver`.
