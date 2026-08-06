#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

python3 - <<'PY'
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


manifest_path = Path("protocols/krikos-identity/Cargo.toml")
source_root = Path("protocols/krikos-identity/src")
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
base_manifest_path = Path("krikos-base/Cargo.toml")
base_source_root = Path("krikos-base/src")
base_manifest = tomllib.loads(base_manifest_path.read_text(encoding="utf-8"))
failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


dependencies = manifest.get("dependencies", {})
getrandom = dependencies.get("getrandom")
if not isinstance(getrandom, dict):
    fail("getrandom must be an explicit dependency table")
else:
    if getrandom.get("optional") is not True:
        fail("getrandom must be optional")
    if getrandom.get("default-features") is not False:
        fail("getrandom default features must remain disabled")

features = manifest.get("features", {})
if features.get("default") != []:
    fail("krikos-identity default features must remain empty")
if features.get("os-rng") != ["dep:getrandom"]:
    fail("os-rng must enable exactly dep:getrandom")
for feature_name, feature_members in features.items():
    if feature_name == "os-rng" or not isinstance(feature_members, list):
        continue
    if "dep:getrandom" in feature_members or "getrandom" in feature_members:
        fail(f"{feature_name} must not enable getrandom")

base_dependency = dependencies.get("krikos-base")
if not isinstance(base_dependency, dict):
    fail("krikos-base must be an explicit dependency table")
else:
    if base_dependency.get("default-features") is not False:
        fail("krikos-identity must disable krikos-base default features")
    if base_dependency.get("features") != ["key-types"]:
        fail("krikos-identity default core must enable exactly krikos-base/key-types")

base_dependencies = base_manifest.get("dependencies", {})
base_rand = base_dependencies.get("rand")
if not isinstance(base_rand, dict) or base_rand.get("optional") is not True:
    fail("krikos-base rand dependency must remain optional")
base_target_dependencies = base_manifest.get("target", {})
base_getrandom_tables = [
    target_table.get("dependencies", {}).get("getrandom")
    for target_table in base_target_dependencies.values()
    if isinstance(target_table, dict)
]
if len(base_getrandom_tables) != 1 or not isinstance(base_getrandom_tables[0], dict):
    fail("krikos-base must declare exactly one target-specific getrandom dependency")
elif base_getrandom_tables[0].get("optional") is not True:
    fail("krikos-base target-specific getrandom dependency must remain optional")

base_features = base_manifest.get("features", {})
if base_features.get("key") != ["os-rng"]:
    fail("krikos-base/key must remain the backward-compatible os-rng aggregate")
os_rng_members = base_features.get("os-rng")
if not isinstance(os_rng_members, list) or set(os_rng_members) != {
    "key-types",
    "dep:getrandom",
    "dep:rand",
}:
    fail("krikos-base/os-rng must enable key types plus only rand and getrandom")


def feature_closure(feature_name: str) -> set[str]:
    pending = [feature_name]
    visited: set[str] = set()
    members: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        current_members = base_features.get(current)
        if not isinstance(current_members, list):
            fail(f"krikos-base feature {current} must exist and be a list")
            continue
        for member in current_members:
            members.add(member)
            if not member.startswith("dep:"):
                pending.append(member)
    return members


key_type_members = feature_closure("key-types")
ambient_base_members = {"key", "os-rng", "dep:getrandom", "dep:rand"}
leaked_base_members = key_type_members.intersection(ambient_base_members)
if leaked_base_members:
    fail(
        "krikos-base/key-types must not enable ambient entropy members "
        f"{sorted(leaked_base_members)}"
    )


OS_CFG = '#[cfg(feature = "os-rng")]'
OS_DOC_CFG = '#[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]'
FUNCTION_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


def function_lines(path: Path, function_name: str) -> list[int]:
    pattern = re.compile(rf"\bfn\s+{re.escape(function_name)}\b")
    return [
        index
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines())
        if pattern.search(line)
    ]


def require_os_cfg(path: Path, line_index: int, *, public: bool) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    expected = [OS_CFG, OS_DOC_CFG] if public else [OS_CFG]
    actual = [line.strip() for line in lines[line_index - len(expected) : line_index]]
    if actual != expected:
        line_number = line_index + 1
        fail(f"{path}:{line_number} must be immediately gated by {expected!r}")


ambient_apis: dict[Path, dict[str, tuple[int, bool]]] = {
    source_root / "key_wrap.rs": {"rotate_group_key": (1, True)},
    source_root / "pairing.rs": {
        "issue": (1, True),
        "generate": (1, True),
    },
    source_root / "privacy.rs": {
        "seal": (2, True),
        "generate": (3, True),
        "os_secret": (1, False),
    },
}
for path, names in ambient_apis.items():
    for function_name, (expected_count, public) in names.items():
        matches = function_lines(path, function_name)
        if len(matches) != expected_count:
            fail(
                f"{path}: expected {expected_count} ambient {function_name} definition(s), "
                f"found {len(matches)}"
            )
            continue
        for line_index in matches:
            require_os_cfg(path, line_index, public=public)


default_rng_apis: dict[Path, dict[str, int]] = {
    source_root / "key_wrap.rs": {"rotate_group_key_with_rng": 1},
    source_root / "pairing.rs": {"issue_with_rng": 1, "generate_with_rng": 1},
    source_root / "privacy.rs": {"seal_with_rng": 2, "generate_with_rng": 3},
}
for path, names in default_rng_apis.items():
    lines = path.read_text(encoding="utf-8").splitlines()
    for function_name, expected_count in names.items():
        matches = function_lines(path, function_name)
        if len(matches) != expected_count:
            fail(
                f"{path}: expected {expected_count} explicit-RNG {function_name} definition(s), "
                f"found {len(matches)}"
            )
            continue
        for line_index in matches:
            prior_lines = [line.strip() for line in lines[max(0, line_index - 3) : line_index]]
            if OS_CFG in prior_lines:
                fail(f"{path}:{line_index + 1} explicit-RNG API must remain in the default core")


for path in source_root.rglob("*.rs"):
    lines = path.read_text(encoding="utf-8").splitlines()
    for call_index, line in enumerate(lines):
        if "getrandom::" not in line:
            continue
        function_index = None
        for candidate_index in range(call_index, -1, -1):
            if FUNCTION_RE.search(lines[candidate_index]):
                function_index = candidate_index
                break
        if function_index is None:
            fail(f"{path}:{call_index + 1} getrandom call is outside a function")
            continue
        prior_lines = [
            candidate.strip()
            for candidate in lines[max(0, function_index - 3) : function_index]
        ]
        if OS_CFG not in prior_lines:
            fail(
                f"{path}:{call_index + 1} getrandom call is not inside an os-rng-gated function"
            )

base_key_path = base_source_root / "key.rs"
base_generate_lines = function_lines(base_key_path, "generate")
if len(base_generate_lines) != 1:
    fail(f"{base_key_path}: expected one SecretKey::generate definition")
else:
    require_os_cfg(base_key_path, base_generate_lines[0], public=True)

base_key_lines = base_key_path.read_text(encoding="utf-8").splitlines()
for call_index, line in enumerate(base_key_lines):
    stripped = line.strip()
    if stripped.startswith("//") or not any(
        ambient_call in stripped for ambient_call in ("rand::random", "rand::rng(", "getrandom::")
    ):
        continue
    function_index = None
    for candidate_index in range(call_index, -1, -1):
        if FUNCTION_RE.search(base_key_lines[candidate_index]):
            function_index = candidate_index
            break
    if function_index is None:
        fail(f"{base_key_path}:{call_index + 1} ambient RNG call is outside a function")
        continue
    prior_lines = [
        candidate.strip()
        for candidate in base_key_lines[max(0, function_index - 3) : function_index]
    ]
    if OS_CFG not in prior_lines:
        fail(f"{base_key_path}:{call_index + 1} ambient RNG call is not os-rng-gated")

base_lib_text = (base_source_root / "lib.rs").read_text(encoding="utf-8")
if base_lib_text.count('#[cfg(feature = "key-types")]') != 4:
    fail("krikos-base key modules and exports must be gated by key-types")
if '#[cfg(feature = "key")]' in base_lib_text:
    fail("krikos-base key modules must not require the ambient-RNG compatibility aggregate")


lib_path = source_root / "lib.rs"
lib_lines = lib_path.read_text(encoding="utf-8").splitlines()
export_line = "pub use key_wrap::rotate_group_key;"
if export_line not in lib_lines:
    fail("lib.rs must expose rotate_group_key through a dedicated feature-gated re-export")
else:
    require_os_cfg(lib_path, lib_lines.index(export_line), public=True)

lib_text = "\n".join(lib_lines)
readme_text = Path("protocols/krikos-identity/README.md").read_text(encoding="utf-8")
if "//! - `os-rng`" not in lib_text:
    fail("crate API feature list must document os-rng")
if "`os-rng`" not in readme_text:
    fail("crate README feature list must document os-rng")


if failures:
    for failure in failures:
        print(f"identity OS RNG boundary: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("identity OS RNG boundary passed")
PY
