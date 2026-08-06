#!/usr/bin/env python3
"""Fail closed until every krikos-identity stable-release criterion is approved."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

PACKAGE_NAME = "krikos-identity"
PACKAGE_PATH = "protocols/krikos-identity"
EXPECTED_PACKAGE = {"name": PACKAGE_NAME, "path": PACKAGE_PATH}
RELEASE_DEPENDENCIES = ("krikos-base", "krikos")
APPROVAL_MESSAGES = {
    "third_party_security_audit": "third-party security audit is not approved",
    "independently_maintained_interoperability": (
        "independently maintained interoperability is not approved"
    ),
    "production_provider_diversity": "production provider diversity is not approved",
    "protocol_governance": "protocol governance is not approved",
    "public_api_semver_baseline": "public API and SemVer baseline is not approved",
    "persistent_schema_support": "persistent-schema support is not approved",
}


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def validate_evidence(policy: dict, approvals: object, failures: list[str]) -> None:
    evidence = policy.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(APPROVAL_MESSAGES):
        failures.append("evidence must contain exactly the reviewed approval names")
        return

    for name, references in evidence.items():
        if not isinstance(references, list) or any(
            not isinstance(reference, str) or not reference.strip()
            for reference in references
        ):
            failures.append(f"evidence for {name} must be a list of non-empty strings")

    if not isinstance(approvals, dict):
        return
    for name, approved in approvals.items():
        if approved is True and not evidence.get(name):
            failures.append(f"approved criterion {name} has no recorded evidence")


def release_package_order(repo_root: Path, failures: list[str]) -> list[str]:
    release_script = (repo_root / "scripts/verify-release-packages.sh").read_text(
        encoding="utf-8"
    )
    match = re.search(r'^packages="([^"]*)"$', release_script, re.MULTILINE)
    if match is None:
        failures.append("the publishable release package order could not be parsed")
        return []
    packages = match.group(1).split()
    if len(packages) != len(set(packages)):
        failures.append("the publishable release package order contains duplicates")
    return packages


def validate(repo_root: Path) -> tuple[dict, list[str]]:
    policy = load_toml(repo_root / PACKAGE_PATH / "release-gate.toml")
    failures: list[str] = []

    if policy.get("schema_version") != 1:
        failures.append("release gate schema_version must be 1")
    if policy.get("package") != EXPECTED_PACKAGE:
        failures.append("release gate package identity differs from krikos-identity")

    status = policy.get("status")
    if status not in {"blocked", "open"}:
        failures.append("release gate status must be blocked or open")

    approvals = policy.get("approvals")
    if not isinstance(approvals, dict) or set(approvals) != set(APPROVAL_MESSAGES):
        failures.append("approvals must contain exactly the reviewed stable-release criteria")
    elif any(not isinstance(value, bool) for value in approvals.values()):
        failures.append("approval values must be booleans")
    validate_evidence(policy, approvals, failures)

    root_manifest = load_toml(repo_root / "Cargo.toml")
    members = root_manifest.get("workspace", {}).get("members", [])
    if PACKAGE_PATH not in members:
        failures.append(f"{PACKAGE_PATH} is not a root workspace member")

    package_manifest = load_toml(repo_root / PACKAGE_PATH / "Cargo.toml").get(
        "package", {}
    )
    if package_manifest.get("name") != PACKAGE_NAME:
        failures.append(f"{PACKAGE_PATH} package name is not {PACKAGE_NAME}")
    if package_manifest.get("version") != {"workspace": True}:
        failures.append(f"{PACKAGE_NAME} must use the coordinated workspace version")

    make_policy = load_toml(repo_root / "Makefile.toml")
    skip_members = make_policy.get("env", {}).get(
        "CARGO_MAKE_WORKSPACE_SKIP_MEMBERS", []
    )
    if not isinstance(skip_members, list) or any(
        not isinstance(member, str) for member in skip_members
    ):
        failures.append("the external-types skip list must be a string list")
        skip_members = []

    release_packages = release_package_order(repo_root, failures)
    release_occurrences = release_packages.count(PACKAGE_NAME)

    if status == "blocked":
        if package_manifest.get("publish") is not False:
            failures.append(
                f"{PACKAGE_NAME} must retain publish = false while the gate is closed"
            )
        if PACKAGE_PATH not in skip_members:
            failures.append(
                f"{PACKAGE_PATH} must remain outside the external-types baseline "
                "while the gate is closed"
            )
        if release_occurrences:
            failures.append(
                f"{PACKAGE_NAME} entered the publishable release order while its gate is closed"
            )
    elif status == "open":
        if (
            "publish" in package_manifest
            and package_manifest.get("publish") is not True
        ):
            failures.append(
                f"{PACKAGE_NAME} publish setting is not open for the stable registry"
            )
        if PACKAGE_PATH in skip_members:
            failures.append(
                f"{PACKAGE_PATH} remains outside the external-types baseline "
                "while its gate is open"
            )
        if release_occurrences != 1:
            failures.append(
                f"{PACKAGE_NAME} must occur exactly once in the publishable release order "
                "while its gate is open"
            )
        else:
            package_index = release_packages.index(PACKAGE_NAME)
            for dependency in RELEASE_DEPENDENCIES:
                if release_packages.count(dependency) != 1:
                    failures.append(
                        f"{dependency} must occur exactly once before {PACKAGE_NAME} "
                        "in the publishable release order"
                    )
                elif release_packages.index(dependency) > package_index:
                    failures.append(
                        f"{PACKAGE_NAME} must follow {dependency} in the publishable "
                        "release order"
                    )

    return policy, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--expect-closed", action="store_true")
    mode.add_argument("--require-open", action="store_true")
    parser.add_argument("--repo-root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    repo_root = (
        args.repo_root.resolve()
        if args.repo_root is not None
        else Path(__file__).resolve().parent.parent
    )

    try:
        policy, failures = validate(repo_root)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"identity release gate: cannot read policy inputs: {error}", file=sys.stderr)
        return 1

    if failures:
        for failure in failures:
            print(f"identity release gate: {failure}", file=sys.stderr)
        return 1

    approvals = policy.get("approvals", {})
    blockers = [
        message
        for name, message in APPROVAL_MESSAGES.items()
        if approvals.get(name) is not True
    ]
    status = policy.get("status")

    if args.expect_closed:
        if status != "blocked" or not blockers:
            print(
                "identity release gate: closed-gate policy is inconsistent",
                file=sys.stderr,
            )
            return 1
        print("krikos-identity stable-release gate is closed as required")
        return 0

    if status != "open" or blockers:
        for blocker in blockers:
            print(f"identity release gate: {blocker}", file=sys.stderr)
        if status != "open":
            print("identity release gate: status is not open", file=sys.stderr)
        return 1

    print("krikos-identity stable-release gate is open")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
