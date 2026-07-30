#!/usr/bin/env python3
"""Tests for the bounded Netsim report validator."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = REPO_ROOT / "scripts" / "validate_netsim_reports.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_netsim_reports", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load validator from {VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load_validator()


class ValidateNetsimReportsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        (self.root / "sims" / "integration").mkdir(parents=True)
        (self.root / "report").mkdir()
        self.config_path = self.root / "sims" / "integration" / "suite.json"
        self.write_json(
            self.config_path,
            {
                "name": "intg_suite",
                "cases": [
                    {
                        "name": "complete",
                        "nodes": [
                            {
                                "name": "client",
                                "count": 2,
                                "parser": "iroh_json",
                                "integration": "magic_iroh_client_json",
                                "integration_require": {
                                    "transfer_success": "true",
                                },
                            }
                        ],
                    },
                    {
                        "name": "skip_me",
                        "nodes": [
                            {
                                "name": "client",
                                "count": 1,
                                "parser": "iroh_json",
                            }
                        ],
                    },
                ],
            },
        )
        self.write_complete_reports()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")

    def write_complete_reports(self) -> None:
        prefix = "intg_suite__complete__client"
        self.write_json(
            self.root / "report" / f"{prefix}.json",
            {"raw": [{"ok": True}, {"ok": True}], "sum": {}, "avg": {}},
        )
        self.write_json(
            self.root / "report" / f"integration_{prefix}.json",
            [
                {"node": "client_0", "transfer_success": "true"},
                {"node": "client_1", "transfer_success": "true"},
            ],
        )

    def validate(self):
        return validator.validate_reports(
            self.root,
            [Path("sims/integration")],
            "skip:intg_suite__skip_me",
        )

    def test_accepts_complete_selected_case(self) -> None:
        summary = self.validate()
        self.assertEqual(summary.selected_cases, 1)
        self.assertEqual(summary.validated_reports, 2)

    def test_rejects_missing_selected_case_report(self) -> None:
        (self.root / "report" / "intg_suite__complete__client.json").unlink()
        with self.assertRaisesRegex(validator.ValidationError, "missing report"):
            self.validate()

    def test_rejects_incomplete_node_count(self) -> None:
        prefix = "intg_suite__complete__client"
        self.write_json(
            self.root / "report" / f"integration_{prefix}.json",
            [{"node": "client_0", "transfer_success": "true"}],
        )
        with self.assertRaisesRegex(validator.ValidationError, "expected 2 entries"):
            self.validate()

    def test_rejects_unmet_integration_requirement(self) -> None:
        prefix = "intg_suite__complete__client"
        self.write_json(
            self.root / "report" / f"integration_{prefix}.json",
            [
                {"node": "client_0", "transfer_success": "true"},
                {"node": "client_1", "transfer_success": "false"},
            ],
        )
        with self.assertRaisesRegex(validator.ValidationError, "transfer_success"):
            self.validate()

    def test_rejects_runner_failure_summary(self) -> None:
        (self.root / "logs").mkdir()
        (self.root / "logs" / "failed_tests.txt").write_text(
            "FAILED: intg_suite__complete\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(validator.ValidationError, "failure summary"):
            self.validate()

    def test_rejects_selected_case_without_reportable_nodes(self) -> None:
        self.write_json(
            self.config_path,
            {
                "name": "intg_suite",
                "cases": [
                    {
                        "name": "complete",
                        "nodes": [{"name": "server", "count": 1}],
                    }
                ],
            },
        )
        with self.assertRaisesRegex(validator.ValidationError, "no reportable nodes"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
