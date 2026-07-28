#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_protocol_provenance as provenance  # noqa: E402
import check_workspace_architecture as architecture  # noqa: E402


SHA_A = "a" * 40
SHA_B = "b" * 40


def package(name: str, dependencies: list[tuple[str, str | None]]) -> dict:
    return {
        "name": name,
        "dependencies": [
            {"name": dependency, "kind": kind, "path": f"/{dependency}"}
            for dependency, kind in dependencies
        ],
    }


def architecture_policy() -> dict:
    return {
        "schema_version": 1,
        "layers": [
            {"name": "foundation", "rank": 0},
            {"name": "platform", "rank": 1},
            {"name": "protocol", "rank": 2},
        ],
        "packages": [
            {
                "name": "base",
                "path": "base",
                "workspace": "root",
                "layer": "foundation",
                "allowed_normal": [],
                "allowed_dev": [],
            },
            {
                "name": "platform",
                "path": "platform",
                "workspace": "root",
                "layer": "platform",
                "allowed_normal": ["base"],
                "allowed_dev": [],
            },
            {
                "name": "protocol",
                "path": "protocols/protocol",
                "workspace": "root",
                "layer": "protocol",
                "allowed_normal": ["platform"],
                "allowed_dev": [],
            },
        ],
    }


def baseline(**overrides: object) -> dict:
    record: dict[str, object] = {
        "name": "iroh-blobs",
        "source_url": "https://github.com/n0-computer/iroh-blobs",
        "tag": "v0.103.0",
        "source_commit": SHA_A,
        "resolved_tag_commit": SHA_A,
        "import_prefix": "protocols/iroh-blobs",
        "state": "pending",
        "expected_license": "MIT OR Apache-2.0",
        "license_files": ["LICENSE-MIT", "LICENSE-APACHE"],
    }
    record.update(overrides)
    return record


class ArchitecturePolicyFixtures(unittest.TestCase):
    def test_upward_platform_dependency_is_rejected(self) -> None:
        policy = architecture_policy()
        policy["packages"][1]["allowed_normal"] = ["protocol"]
        metadata = {
            "packages": [
                package("base", []),
                package("platform", [("protocol", None)]),
                package("protocol", [("platform", None)]),
            ]
        }

        failures = architecture.validate_architecture(
            policy, metadata, {"packages": []}, Path("/nonexistent")
        )

        self.assertIn(
            "upward first-party dependency: platform (platform) -> protocol (protocol)",
            failures,
        )

    def test_unmanaged_protocol_manifest_is_rejected(self) -> None:
        policy = architecture_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "protocols" / "unmanaged" / "Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text('[package]\nname = "unmanaged"\nversion = "0.1.0"\n')

            failures = architecture.validate_architecture(
                policy,
                {"packages": [package("base", []), package("platform", [])]},
                {"packages": []},
                root,
            )

        self.assertIn(
            "unmanaged protocol manifest: protocols/unmanaged/Cargo.toml", failures
        )


class ProvenancePolicyFixtures(unittest.TestCase):
    def test_floating_source_ref_is_rejected(self) -> None:
        failures = provenance.validate_baselines(
            {"schema_version": 1, "baselines": [baseline(tag="main")]},
            Path("/nonexistent"),
        )

        self.assertIn("iroh-blobs.tag must be an exact release tag, found 'main'", failures)

    def test_duplicate_import_prefix_is_rejected(self) -> None:
        duplicate = baseline(name="iroh-gossip")
        failures = provenance.validate_baselines(
            {"schema_version": 1, "baselines": [baseline(), duplicate]},
            Path("/nonexistent"),
        )

        self.assertIn(
            "duplicate import_prefix 'protocols/iroh-blobs': iroh-blobs, iroh-gossip",
            failures,
        )

    def test_missing_license_is_rejected_after_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "protocols" / "iroh-blobs"
            prefix.mkdir(parents=True)
            (prefix / "Cargo.toml").write_text(
                '[package]\nname = "iroh-blobs"\nversion = "0.103.0"\n'
                'license = "MIT OR Apache-2.0"\n'
            )
            (prefix / "UPSTREAM.md").write_text("# Upstream\n")

            failures = provenance.validate_baselines(
                {
                    "schema_version": 1,
                    "baselines": [baseline(state="imported")],
                },
                root,
            )

        self.assertIn(
            "iroh-blobs license file missing: protocols/iroh-blobs/LICENSE-MIT",
            failures,
        )

    def test_baseline_sha_must_resolve_from_tag(self) -> None:
        failures = provenance.validate_baselines(
            {
                "schema_version": 1,
                "baselines": [baseline(resolved_tag_commit=SHA_B)],
            },
            Path("/nonexistent"),
        )

        self.assertIn(
            f"iroh-blobs source_commit {SHA_A} does not resolve from tag v0.103.0 ({SHA_B})",
            failures,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
