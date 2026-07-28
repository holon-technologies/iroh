#!/usr/bin/env python3
"""Validate that a bounded Netsim selection produced complete reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, NamedTuple


class ValidationError(RuntimeError):
    """Raised when selected Netsim evidence is missing or invalid."""


class ValidationSummary(NamedTuple):
    """Counts returned after successful evidence validation."""

    selected_cases: int
    validated_reports: int


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"could not read JSON from {path}: {error}") from error


def _config_files(netsim_root: Path, sim_paths: list[Path]) -> list[Path]:
    config_files: list[Path] = []
    seen: set[Path] = set()
    for relative_path in sim_paths:
        path = netsim_root / relative_path
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = sorted(path.rglob("*.json"))
        else:
            raise ValidationError(f"Netsim path does not exist: {relative_path}")
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                config_files.append(candidate)
    if not config_files:
        raise ValidationError("selected Netsim paths contain no configurations")
    return config_files


def _filter_lists(filter_value: str) -> tuple[list[str], list[str]]:
    if not filter_value:
        return [], []
    if filter_value.startswith("skip:"):
        return filter_value.removeprefix("skip:").split(","), []
    if filter_value.startswith("only:"):
        return [], filter_value.removeprefix("only:").split(",")
    return [], filter_value.split(",")


def _selected(prefix: str, skip: list[str], only: list[str]) -> bool:
    if only and not any(value in prefix for value in only):
        return False
    return not any(value in prefix for value in skip)


def _expect_list(path: Path, value: Any, expected_count: int) -> list[Any]:
    if not isinstance(value, list):
        raise ValidationError(f"report must contain a JSON array: {path}")
    if len(value) != expected_count:
        raise ValidationError(
            f"report {path} expected {expected_count} entries, found {len(value)}"
        )
    return value


def _validate_raw_report(path: Path, expected_count: int) -> None:
    if not path.is_file():
        raise ValidationError(f"missing report for selected case: {path}")
    report = _load_json(path)
    if not isinstance(report, dict) or "raw" not in report:
        raise ValidationError(f"raw report has an invalid schema: {path}")
    _expect_list(path, report["raw"], expected_count)


def _validate_integration_report(
    path: Path, expected_count: int, requirements: dict[str, Any]
) -> None:
    if not path.is_file():
        raise ValidationError(f"missing report for selected case: {path}")
    entries = _expect_list(path, _load_json(path), expected_count)
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValidationError(f"integration report entry {index} is invalid: {path}")
        for field, expected in requirements.items():
            actual = entry.get(field)
            if str(actual).lower() != str(expected).lower():
                raise ValidationError(
                    f"integration requirement failed in {path} entry {index}: "
                    f"{field}={actual!r}, expected {expected!r}"
                )


def validate_reports(
    netsim_root: Path, sim_paths: list[Path], filter_value: str = ""
) -> ValidationSummary:
    """Validate report evidence for every case selected by Netsim's filter rules."""

    netsim_root = netsim_root.resolve()
    failure_summary = netsim_root / "logs" / "failed_tests.txt"
    if failure_summary.is_file():
        try:
            failure_text = failure_summary.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ValidationError(
                f"could not read Netsim failure summary: {error}"
            ) from error
        if failure_text:
            raise ValidationError(
                f"Netsim runner produced a failure summary: {failure_summary}"
            )
    skip, only = _filter_lists(filter_value)
    selected_cases = 0
    validated_reports = 0

    for config_path in _config_files(netsim_root, sim_paths):
        config = _load_json(config_path)
        if not isinstance(config, dict):
            raise ValidationError(f"Netsim configuration must be an object: {config_path}")
        name = config.get("name")
        cases = config.get("cases")
        if not isinstance(name, str) or not isinstance(cases, list):
            raise ValidationError(f"Netsim configuration has an invalid schema: {config_path}")

        for case in cases:
            if not isinstance(case, dict) or not isinstance(case.get("name"), str):
                raise ValidationError(f"Netsim case has an invalid schema: {config_path}")
            case_prefix = f"{name}__{case['name']}"
            if not _selected(case_prefix, skip, only):
                continue
            selected_cases += 1
            nodes = case.get("nodes")
            if not isinstance(nodes, list):
                raise ValidationError(f"Netsim case has invalid nodes: {case_prefix}")
            case_reports = 0

            for node in nodes:
                if not isinstance(node, dict) or not isinstance(node.get("name"), str):
                    raise ValidationError(f"Netsim node has an invalid schema: {case_prefix}")
                count = node.get("count", 1)
                if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                    raise ValidationError(
                        f"Netsim node has an invalid count: {case_prefix}__{node['name']}"
                    )
                report_prefix = f"{case_prefix}__{node['name']}"
                if "parser" in node:
                    _validate_raw_report(
                        netsim_root / "report" / f"{report_prefix}.json", count
                    )
                    case_reports += 1
                if "integration" in node:
                    requirements = node.get("integration_require", {})
                    if not isinstance(requirements, dict):
                        raise ValidationError(
                            f"integration requirements must be an object: {report_prefix}"
                        )
                    _validate_integration_report(
                        netsim_root
                        / "report"
                        / f"integration_{report_prefix}.json",
                        count,
                        requirements,
                    )
                    case_reports += 1

            if case_reports == 0:
                raise ValidationError(
                    f"selected case has no reportable nodes: {case_prefix}"
                )
            validated_reports += case_reports

    if selected_cases == 0:
        raise ValidationError("Netsim filter selected no cases")
    return ValidationSummary(selected_cases, validated_reports)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--netsim-root", required=True, type=Path)
    parser.add_argument("--filter", default="")
    parser.add_argument("sim_paths", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        summary = validate_reports(args.netsim_root, args.sim_paths, args.filter)
    except ValidationError as error:
        print(f"Netsim report validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Netsim report validation passed: "
        f"cases={summary.selected_cases} reports={summary.validated_reports}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
