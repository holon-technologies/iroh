#!/usr/bin/env python3
"""Generate exact numeric-selector sync fuzz seeds from canonical interop vectors."""

from __future__ import annotations

import argparse
from pathlib import Path


MAX_FUZZ_INPUT_BYTES = 4 * 1024 * 1024 + 1
ACCEPTED_VECTORS = (
    (0, "sync-request", "sync-request"),
    (1, "sync-frame", "sync-frame"),
    (2, "sync-cursor", "sync-cursor"),
    (3, "sync-response", "sync-response-frame"),
    (4, "endpoint-authorization", "endpoint-authorization-request"),
    (5, "authorized-sync", "authorized-sync-request"),
    (6, "authorized-proposal", "authorized-proposal-request"),
    (7, "authorized-checkpoint", "authorized-checkpoint-request"),
    (8, "identity-protocol-ack", "identity-protocol-ack"),
    (9, "identity-protocol-reply", "identity-protocol-reply-ack"),
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
        default=repository / "fuzz/corpus/identity_sync",
    )
    return parser.parse_args()


def seed_name(selector: int, name: str, suffix: str) -> str:
    return f"selector-{selector:02x}-{name}-{suffix}.bin"


def with_selector(selector: int, payload: bytes) -> bytes:
    seed = bytes([selector]) + payload
    if len(seed) > MAX_FUZZ_INPUT_BYTES:
        raise ValueError(
            f"selector {selector} seed is {len(seed)} bytes; "
            f"maximum is {MAX_FUZZ_INPUT_BYTES}"
        )
    return seed


def duplicate_single_head(payload: bytes) -> bytes:
    # V1 + AccountId (algorithm code plus 32-byte digest) precede the bounded head vector.
    head_count_offset = 1 + 33
    if payload[0] != 1 or payload[head_count_offset] != 1:
        raise ValueError("sync fixture must carry v1 and exactly one source head")
    head_offset = head_count_offset + 1
    head_end = head_offset + 33
    head = payload[head_offset:head_end]
    if len(head) != 33:
        raise ValueError("sync fixture has a truncated algorithm-tagged head")
    return payload[:head_count_offset] + bytes([2]) + head + head + payload[head_end:]


def replace_byte(payload: bytes, offset: int, value: int) -> bytes:
    changed = bytearray(payload)
    if changed[offset] == value:
        raise ValueError(f"replacement at offset {offset} must change the fixture")
    changed[offset] = value
    return bytes(changed)


def main() -> None:
    options = arguments()
    options.output_directory.mkdir(parents=True, exist_ok=True)
    accepted: dict[int, tuple[str, bytes]] = {}
    for selector, corpus_name, vector_name in ACCEPTED_VECTORS:
        payload = (options.vector_directory / f"{vector_name}.bin").read_bytes()
        if not payload:
            raise ValueError(f"canonical vector {vector_name}.bin must not be empty")
        accepted[selector] = (corpus_name, payload)
        (options.output_directory / seed_name(selector, corpus_name, "accepted")).write_bytes(
            with_selector(selector, payload)
        )
        (
            options.output_directory
            / seed_name(selector, corpus_name, "rejected-truncated")
        ).write_bytes(with_selector(selector, payload[:-1]))

    for selector in (0, 1, 2):
        corpus_name, payload = accepted[selector]
        (
            options.output_directory
            / seed_name(selector, corpus_name, "rejected-duplicate-head")
        ).write_bytes(with_selector(selector, duplicate_single_head(payload)))

    for selector in (0, 1, 2, 3):
        corpus_name, payload = accepted[selector]
        (
            options.output_directory
            / seed_name(selector, corpus_name, "rejected-unsupported-version")
        ).write_bytes(with_selector(selector, replace_byte(payload, 0, 2)))

    response_name, response_payload = accepted[3]
    (
        options.output_directory
        / seed_name(3, response_name, "rejected-legacy-ordinal")
    ).write_bytes(with_selector(3, replace_byte(response_payload, 1, 0)))
    (
        options.output_directory
        / seed_name(3, response_name, "rejected-unsupported-codepoint")
    ).write_bytes(with_selector(3, replace_byte(response_payload, 1, 3)))

    for selector in (5, 6, 7):
        corpus_name, payload = accepted[selector]
        account_mismatch = bytearray(payload)
        account_mismatch[2] ^= 0xFF
        (
            options.output_directory
            / seed_name(selector, corpus_name, "rejected-account-mismatch")
        ).write_bytes(with_selector(selector, bytes(account_mismatch)))


if __name__ == "__main__":
    main()
