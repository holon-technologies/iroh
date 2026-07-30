//! Test-only loader for immutable relay compatibility fixtures.

use data_encoding::HEXLOWER;

const FIXTURES: &str = include_str!("../../tests/fixtures/compat/v1.0.3/wire.txt");
const MAX_FIXTURE_LINES: usize = 64;
const MAX_FIXTURE_BYTES: usize = 1024 * 1024;

pub(crate) fn fixture(name: &str) -> Vec<u8> {
    assert!(
        name.len() <= 128,
        "compatibility fixture name must remain bounded"
    );

    for line in FIXTURES.lines().take(MAX_FIXTURE_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((candidate, encoded)) = line.split_once('=') else {
            panic!("compatibility fixture line must contain '=': {line}");
        };
        if candidate != name {
            continue;
        }
        assert!(
            encoded.len() <= MAX_FIXTURE_BYTES * 2,
            "compatibility fixture must remain bounded"
        );
        return HEXLOWER
            .decode(encoded.as_bytes())
            .expect("reviewed compatibility fixture must contain lowercase hexadecimal");
    }

    panic!("missing compatibility fixture: {name}");
}
