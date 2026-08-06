#!/usr/bin/env python3
"""Generate the provider interchange fuzz seeds from canonical interop vectors."""

from __future__ import annotations

import argparse
from pathlib import Path


MAX_FUZZ_INPUT_BYTES = 4_096
PROVIDER_INTERCHANGE_SEEDS = (
    ("7", "provider-export-component"),
    ("8", "provider-export-component-descriptor"),
    ("9", "provider-generation-export-chunk"),
    ("a", "provider-audit-export-chunk"),
    ("b", "provider-generation-export-manifest"),
    ("c", "provider-audit-export-manifest"),
    ("d", "provider-recovery-export-manifest"),
    ("e", "provider-compaction-manifest"),
    ("f", "opaque-provider-anchor-commitment"),
)


def arguments() -> argparse.Namespace:
    repository = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "vector_directory",
        nargs="?",
        type=Path,
        default=repository / "protocols/krikos-identity/tests/vectors",
    )
    parser.add_argument(
        "output_directory",
        nargs="?",
        type=Path,
        default=repository / "fuzz/corpus/identity_provider",
    )
    return parser.parse_args()


def seed_name(selector: str, vector_name: str, suffix: str) -> str:
    selector_code = int(selector, 16)
    return f"selector-{selector_code:02x}-{vector_name}-{suffix}.bin"


def main() -> None:
    options = arguments()
    options.output_directory.mkdir(parents=True, exist_ok=True)
    for selector, vector_name in PROVIDER_INTERCHANGE_SEEDS:
        payload = (options.vector_directory / f"{vector_name}.bin").read_bytes()
        if not payload:
            raise ValueError(f"canonical vector {vector_name}.bin must not be empty")

        accepted = selector.encode("ascii") + payload
        malformed = selector.encode("ascii") + payload[:-1]
        if len(accepted) > MAX_FUZZ_INPUT_BYTES:
            raise ValueError(
                f"{vector_name} seed is {len(accepted)} bytes; "
                f"maximum is {MAX_FUZZ_INPUT_BYTES}"
            )

        (options.output_directory / seed_name(selector, vector_name, "accepted")).write_bytes(
            accepted
        )
        (
            options.output_directory
            / seed_name(selector, vector_name, "malformed-truncated")
        ).write_bytes(malformed)


if __name__ == "__main__":
    main()
