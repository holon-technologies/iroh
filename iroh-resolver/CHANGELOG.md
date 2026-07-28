# Changelog

All notable changes to iroh-resolver will be documented in this file.

## Unreleased

### Features

- Extracted generic A, AAAA, TXT, and host resolution from `iroh-dns`.
- Added explicit Ring and AWS-LC provider features for encrypted DNS transports.
- Preserved deterministic timeout, stagger, cache clearing, and atomic reset capabilities.

### Compatibility

- This is the first published release of `iroh-resolver`.
- Endpoint-record lookup now composes this crate through `iroh-dns::dns::EndpointDnsResolver`.
