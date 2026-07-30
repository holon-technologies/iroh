#!/usr/bin/env python3
"""Fail closed until provisional framework package and support decisions are approved."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

EXPECTED_PACKAGES = (
    (1, "krikos-blobs", "protocols/krikos-blobs"),
    (2, "krikos-gossip", "protocols/krikos-gossip"),
    (3, "krikos-docs", "protocols/krikos-docs"),
    (4, "krikos-app", "framework/app"),
)
APPROVAL_MESSAGES = {
    "package_naming": "package naming is not approved",
    "registry_ownership": "registry ownership is not approved",
    "public_api_baseline": "the public API baseline is not approved",
    "data_schema_support": "the data schema support commitment is not approved",
}


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def validate(repo_root: Path) -> tuple[dict, list[str]]:
    policy_path = repo_root / "framework/release-gate.toml"
    policy = load_toml(policy_path)
    failures: list[str] = []
    if policy.get("schema_version") != 1:
        failures.append("framework release gate schema_version must be 1")
    records = policy.get("packages")
    expected_records = [
        {"order": order, "name": name, "path": path}
        for order, name, path in EXPECTED_PACKAGES
    ]
    if records != expected_records:
        failures.append("framework package order or identity differs from the reviewed graph")

    root_manifest = load_toml(repo_root / "Cargo.toml")
    members = set(root_manifest.get("workspace", {}).get("members", []))
    for _, expected_name, relative_path in EXPECTED_PACKAGES:
        if relative_path not in members:
            failures.append(f"{relative_path} is not a root workspace member")
            continue
        manifest_path = repo_root / relative_path / "Cargo.toml"
        if not manifest_path.is_file():
            failures.append(f"package manifest is missing: {relative_path}/Cargo.toml")
            continue
        package = load_toml(manifest_path).get("package", {})
        if package.get("name") != expected_name:
            failures.append(f"{relative_path} package name is not {expected_name}")
        if package.get("publish") is not False:
            failures.append(f"{expected_name} must retain publish = false while the gate is closed")
        if package.get("version") != {"workspace": True}:
            failures.append(f"{expected_name} must use the coordinated workspace version")

    make_policy = load_toml(repo_root / "Makefile.toml")
    skip_members = set(
        make_policy.get("env", {}).get("CARGO_MAKE_WORKSPACE_SKIP_MEMBERS", [])
    )
    for _, _, relative_path in EXPECTED_PACKAGES:
        if relative_path not in skip_members:
            failures.append(
                f"{relative_path} must remain outside the external-type baseline until API approval"
            )
    release_packages = (repo_root / "scripts/verify-release-packages.sh").read_text(
        encoding="utf-8"
    )
    release_order_match = re.search(r'^packages="([^"]*)"$', release_packages, re.MULTILINE)
    if release_order_match is None:
        failures.append("the publishable release package order could not be parsed")
        release_package_names: set[str] = set()
    else:
        release_package_names = set(release_order_match.group(1).split())
    for _, package_name, _ in EXPECTED_PACKAGES:
        if package_name in release_package_names:
            failures.append(
                f"{package_name} entered the publishable release order while its gate is closed"
            )
    approvals = policy.get("approvals")
    if not isinstance(approvals, dict) or set(approvals) != set(APPROVAL_MESSAGES):
        failures.append("framework approvals must contain exactly the reviewed decision names")
    elif any(not isinstance(value, bool) for value in approvals.values()):
        failures.append("framework approval values must be booleans")
    return policy, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--expect-closed", action="store_true")
    mode.add_argument("--require-open", action="store_true")
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    policy, failures = validate(repo_root)
    if failures:
        for failure in failures:
            print(f"framework release gate: {failure}", file=sys.stderr)
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
                "framework release gate: closed-gate policy is inconsistent",
                file=sys.stderr,
            )
            return 1
        print("framework release gate is closed as required")
        return 0

    if status != "open" or blockers:
        for blocker in blockers:
            print(f"framework release gate: {blocker}", file=sys.stderr)
        if status != "open":
            print("framework release gate: status is not open", file=sys.stderr)
        return 1
    print("framework release gate is open")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
