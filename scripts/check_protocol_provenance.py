#!/usr/bin/env python3
"""Validate pinned upstream protocol provenance, with optional remote auditing."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
TAG_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
STATES = {"pending", "imported", "ported"}


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def resolve_package_field(manifest: dict, repo_root: Path, field: str) -> object:
    """Resolve a package field, including Cargo's `{ workspace = true }` form."""
    value = manifest.get("package", {}).get(field)
    if value == {"workspace": True}:
        workspace_manifest_path = repo_root / "Cargo.toml"
        if not workspace_manifest_path.is_file():
            return None
        workspace_manifest = load_toml(workspace_manifest_path)
        return workspace_manifest.get("workspace", {}).get("package", {}).get(field)
    return value


def validate_baselines(policy: dict, repo_root: Path) -> list[str]:
    failures: list[str] = []
    if policy.get("schema_version") != 1:
        failures.append("schema_version must be 1")

    baselines = policy.get("baselines", [])
    if not isinstance(baselines, list):
        return failures + ["baselines must be an array of tables"]

    names: dict[str, list[str]] = {}
    prefixes: dict[str, list[str]] = {}
    for index, record in enumerate(baselines):
        name = record.get("name")
        label = name if isinstance(name, str) and name else f"baseline[{index}]"
        if not isinstance(name, str) or not name:
            failures.append(f"{label}.name must be a non-empty string")
            continue
        names.setdefault(name, []).append(name)

        source_url = record.get("source_url")
        if not isinstance(source_url, str):
            failures.append(f"{name}.source_url must be an HTTPS repository URL")
        else:
            parsed = urlparse(source_url)
            if (
                parsed.scheme != "https"
                or not parsed.netloc
                or not parsed.path.strip("/")
                or parsed.query
                or parsed.fragment
            ):
                failures.append(f"{name}.source_url must be an HTTPS repository URL")

        tag = record.get("tag")
        if not isinstance(tag, str) or TAG_PATTERN.fullmatch(tag) is None:
            failures.append(f"{name}.tag must be an exact release tag, found {tag!r}")

        source_commit = record.get("source_commit")
        if not isinstance(source_commit, str) or SHA_PATTERN.fullmatch(source_commit) is None:
            failures.append(f"{name}.source_commit must be a lowercase 40-character SHA")
        resolved = record.get("resolved_tag_commit")
        if not isinstance(resolved, str) or SHA_PATTERN.fullmatch(resolved) is None:
            failures.append(
                f"{name}.resolved_tag_commit must be a lowercase 40-character SHA"
            )
        elif isinstance(source_commit, str) and source_commit != resolved:
            failures.append(
                f"{name} source_commit {source_commit} does not resolve from tag {tag} ({resolved})"
            )

        prefix = record.get("import_prefix")
        if not isinstance(prefix, str) or not prefix:
            failures.append(f"{name}.import_prefix must be protocols/<component>")
        else:
            path = PurePosixPath(prefix)
            if (
                path.is_absolute()
                or len(path.parts) != 2
                or path.parts[0] != "protocols"
                or path.parts[1] in {"", ".", ".."}
            ):
                failures.append(f"{name}.import_prefix must be protocols/<component>")
            prefixes.setdefault(prefix, []).append(name)

        state = record.get("state")
        if state not in STATES:
            failures.append(
                f"{name}.state must be pending, imported, or ported, found {state!r}"
            )
        expected_license = record.get("expected_license")
        if not isinstance(expected_license, str) or not expected_license:
            failures.append(f"{name}.expected_license must be a non-empty SPDX expression")
        license_files = record.get("license_files")
        if not isinstance(license_files, list) or not license_files or not all(
            isinstance(item, str)
            and item
            and PurePosixPath(item).name == item
            for item in license_files
        ):
            failures.append(f"{name}.license_files must contain safe file names")

        if state in {"imported", "ported"} and isinstance(prefix, str):
            imported_root = repo_root / prefix
            for required in ("Cargo.toml", "UPSTREAM.md"):
                if not (imported_root / required).is_file():
                    failures.append(f"{name} required file missing: {prefix}/{required}")
            if isinstance(license_files, list):
                for license_file in license_files:
                    if isinstance(license_file, str) and not (
                        imported_root / license_file
                    ).is_file():
                        failures.append(
                            f"{name} license file missing: {prefix}/{license_file}"
                        )
            manifest_path = imported_root / "Cargo.toml"
            if manifest_path.is_file() and isinstance(expected_license, str):
                manifest = load_toml(manifest_path)
                actual_license = resolve_package_field(manifest, repo_root, "license")
                if actual_license != expected_license:
                    failures.append(
                        f"{name} package.license must be {expected_license!r}, "
                        f"found {actual_license!r}"
                    )

    for name, owners in names.items():
        if len(owners) > 1:
            failures.append(f"duplicate baseline name: {name}")
    for prefix, owners in prefixes.items():
        if len(owners) > 1:
            failures.append(f"duplicate import_prefix {prefix!r}: {', '.join(owners)}")
    return failures


def resolve_remote_tag(source_url: str, tag: str) -> str:
    result = subprocess.run(
        [
            "git",
            "ls-remote",
            "--exit-code",
            source_url,
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"git ls-remote exited {result.returncode}"
        raise RuntimeError(detail)
    refs = {}
    for line in result.stdout.splitlines():
        sha, ref = line.split(maxsplit=1)
        refs[ref] = sha
    peeled = refs.get(f"refs/tags/{tag}^{{}}")
    direct = refs.get(f"refs/tags/{tag}")
    resolved = peeled or direct
    if resolved is None:
        raise RuntimeError(f"remote did not return refs/tags/{tag}")
    return resolved


def audit_remote_tags(policy: dict) -> tuple[list[str], list[str]]:
    mismatches: list[str] = []
    infrastructure: list[str] = []
    for record in policy.get("baselines", []):
        name = record.get("name", "unknown")
        try:
            resolved = resolve_remote_tag(record["source_url"], record["tag"])
        except (KeyError, RuntimeError, subprocess.SubprocessError) as error:
            infrastructure.append(f"{name} remote audit unavailable: {error}")
            continue
        expected = record.get("source_commit")
        if resolved != expected:
            mismatches.append(
                f"{name} remote tag {record.get('tag')} resolves to {resolved}, expected {expected}"
            )
    return mismatches, infrastructure


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--remote", action="store_true")
    args = parser.parse_args()

    policy = load_toml(args.policy)
    failures = validate_baselines(policy, args.repo_root)
    if failures:
        for failure in failures:
            print(f"protocol provenance contract: {failure}", file=sys.stderr)
        return 1
    if args.remote:
        mismatches, infrastructure = audit_remote_tags(policy)
        for mismatch in mismatches:
            print(f"protocol provenance mismatch: {mismatch}", file=sys.stderr)
        for failure in infrastructure:
            print(f"protocol provenance infrastructure: {failure}", file=sys.stderr)
        if mismatches:
            return 1
        if infrastructure:
            return 2
        print("protocol provenance remote audit passed")
        return 0
    print("protocol provenance contract passed (network-free)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
