#!/usr/bin/env python3
"""Validate first-party Cargo edges against the committed architecture policy."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def _dependency_names(package: dict, kind: str, managed: set[str]) -> set[str]:
    expected_kinds: tuple[str | None, ...]
    if kind == "normal":
        expected_kinds = (None, "normal")
    else:
        expected_kinds = (kind,)
    return {
        dependency["name"]
        for dependency in package.get("dependencies", [])
        if dependency.get("kind") in expected_kinds and dependency["name"] in managed
    }


def validate_architecture(
    policy: dict, root_metadata: dict, sim_metadata: dict, repo_root: Path
) -> list[str]:
    failures: list[str] = []
    if policy.get("schema_version") != 1:
        failures.append("schema_version must be 1")

    layers: dict[str, int] = {}
    for record in policy.get("layers", []):
        name = record.get("name")
        rank = record.get("rank")
        if not isinstance(name, str) or not name:
            failures.append("layer.name must be a non-empty string")
            continue
        if name in layers:
            failures.append(f"duplicate layer name: {name}")
            continue
        if not isinstance(rank, int) or rank < 0:
            failures.append(f"layer {name}.rank must be a non-negative integer")
            continue
        layers[name] = rank

    records: dict[str, dict] = {}
    paths: dict[str, str] = {}
    for record in policy.get("packages", []):
        name = record.get("name")
        path = record.get("path")
        if not isinstance(name, str) or not name:
            failures.append("package.name must be a non-empty string")
            continue
        if name in records:
            failures.append(f"duplicate package name: {name}")
            continue
        if not isinstance(path, str) or not path:
            failures.append(f"package {name}.path must be a non-empty string")
            continue
        if path in paths:
            failures.append(f"duplicate package path {path!r}: {paths[path]}, {name}")
            continue
        if record.get("workspace") not in {"root", "sim"}:
            failures.append(f"package {name}.workspace must be 'root' or 'sim'")
        layer = record.get("layer")
        if layer not in layers:
            failures.append(f"package {name}.layer references unknown layer {layer!r}")
        for field in ("allowed_normal", "allowed_dev"):
            value = record.get(field)
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                failures.append(f"package {name}.{field} must be a list of package names")
        records[name] = record
        paths[path] = name

    managed = set(records)
    for name, record in records.items():
        for field in ("allowed_normal", "allowed_dev"):
            for dependency in record.get(field, []):
                if dependency not in managed:
                    failures.append(
                        f"package {name}.{field} references unmanaged package {dependency}"
                    )

    root_packages = {
        package["name"]: package for package in root_metadata.get("packages", [])
    }
    sim_packages = {
        package["name"]: package for package in sim_metadata.get("packages", [])
    }
    expected_root = {
        name for name, record in records.items() if record.get("workspace") == "root"
    }
    expected_sim = {
        name for name, record in records.items() if record.get("workspace") == "sim"
    }
    actual_root = set(root_packages)
    actual_sim = set(sim_packages)
    for name in sorted(actual_root - expected_root):
        failures.append(f"root workspace package is unmanaged: {name}")
    for name in sorted(expected_root - actual_root):
        failures.append(f"managed root workspace package is missing: {name}")
    for name in sorted(actual_sim - expected_sim):
        failures.append(f"sim workspace package is unmanaged: {name}")
    for name in sorted(expected_sim - actual_sim):
        failures.append(f"managed sim workspace package is missing: {name}")

    all_packages = root_packages | sim_packages
    for name, package in all_packages.items():
        record = records.get(name)
        if record is None:
            continue
        for kind, field in (("normal", "allowed_normal"), ("dev", "allowed_dev")):
            actual = _dependency_names(package, kind, managed)
            allowed = set(record.get(field, []))
            unexpected = sorted(actual - allowed)
            if unexpected:
                failures.append(
                    f"forbidden {kind} first-party edges from {name}: {unexpected}"
                )
            owner_layer = record.get("layer")
            owner_rank = layers.get(owner_layer)
            for dependency in sorted(actual):
                dependency_layer = records[dependency].get("layer")
                dependency_rank = layers.get(dependency_layer)
                if (
                    owner_rank is not None
                    and dependency_rank is not None
                    and dependency_rank > owner_rank
                ):
                    failures.append(
                        "upward first-party dependency: "
                        f"{name} ({owner_layer}) -> {dependency} ({dependency_layer})"
                    )

        build_dependencies = _dependency_names(package, "build", managed)
        if build_dependencies:
            failures.append(
                f"forbidden build first-party edges from {name}: {sorted(build_dependencies)}"
            )

    protocols_root = repo_root / "protocols"
    if protocols_root.is_dir():
        managed_manifests = {
            Path(record["path"]) / "Cargo.toml"
            for record in records.values()
            if isinstance(record.get("path"), str)
            and record["path"].startswith("protocols/")
        }
        for manifest in sorted(protocols_root.glob("*/Cargo.toml")):
            relative = manifest.relative_to(repo_root)
            if relative not in managed_manifests:
                failures.append(f"unmanaged protocol manifest: {relative.as_posix()}")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--root-metadata", type=Path, required=True)
    parser.add_argument("--sim-metadata", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()

    failures = validate_architecture(
        load_toml(args.policy),
        json.loads(args.root_metadata.read_text()),
        json.loads(args.sim_metadata.read_text()),
        args.repo_root,
    )
    if failures:
        for failure in failures:
            print(f"workspace architecture contract: {failure}", file=sys.stderr)
        return 1
    print("workspace architecture policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
