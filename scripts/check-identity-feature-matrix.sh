#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

identity_toolchain=${KRIKOS_IDENTITY_TOOLCHAIN:-1.91.0}
static_only=false

usage() {
  printf 'usage: %s [--static-only]\n' "${0##*/}" >&2
}

case $# in
  0) ;;
  1)
    if [[ "$1" != "--static-only" ]]; then
      usage
      exit 2
    fi
    static_only=true
    ;;
  *)
    usage
    exit 2
    ;;
esac

# Keep the executable matrix coupled to the manifest boundary. This fast pass is
# also used by source-contract tests, where compiling every feature combination
# would duplicate the identity CI gate.
python3 - <<'PY'
from __future__ import annotations

import sys
import tomllib
from pathlib import Path


manifest = tomllib.loads(
    Path("protocols/krikos-identity/Cargo.toml").read_text(encoding="utf-8")
)
workspace = tomllib.loads(Path("Cargo.toml").read_text(encoding="utf-8"))
failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


if manifest.get("package", {}).get("rust-version", {}).get("workspace") is not True:
    fail("krikos-identity must inherit the workspace Rust version")
if workspace.get("workspace", {}).get("package", {}).get("rust-version") != "1.91":
    fail("the identity feature matrix is pinned to workspace Rust 1.91")

expected_features = {
    "default": [],
    "fs-store": ["dep:redb"],
    "net": ["dep:krikos", "dep:tokio", "dep:tokio-util"],
    "os-rng": ["dep:getrandom"],
    "provider-store": ["dep:redb"],
}
features = manifest.get("features")
if features != expected_features:
    fail(
        "krikos-identity feature declarations must match the reviewed matrix; "
        f"expected {expected_features!r}, found {features!r}"
    )

dependencies = manifest.get("dependencies", {})
base = dependencies.get("krikos-base")
if not isinstance(base, dict):
    fail("krikos-base must use an explicit dependency table")
else:
    if base.get("default-features") is not False:
        fail("krikos-base default features must remain disabled")
    if base.get("features") != ["key-types"]:
        fail("the default identity core must request only krikos-base/key-types")
    if base.get("optional") is True:
        fail("krikos-base must remain in the no-default normal dependency tree")

for dependency_name in ("getrandom", "krikos", "redb", "tokio", "tokio-util"):
    dependency = dependencies.get(dependency_name)
    if not isinstance(dependency, dict) or dependency.get("optional") is not True:
        fail(f"{dependency_name} must remain an optional normal dependency")

if "rand" in dependencies:
    fail("krikos-identity must not acquire a direct rand dependency")

for target_name, target_table in manifest.get("target", {}).items():
    target_dependencies = target_table.get("dependencies", {})
    for dependency_name, dependency in target_dependencies.items():
        package_name = dependency_name
        is_optional = False
        if isinstance(dependency, dict):
            package_name = dependency.get("package", dependency_name)
            is_optional = dependency.get("optional") is True
        forbidden_target_packages = {
            "getrandom",
            "krikos",
            "rand",
            "redb",
            "tokio",
            "tokio-util",
        }
        if package_name in forbidden_target_packages and not is_optional:
            fail(
                f"target {target_name!r} must not add non-optional default dependency "
                f"{package_name!r}"
            )

if failures:
    for failure in failures:
        print(f"identity feature matrix: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("identity feature matrix static contract passed")
PY

scripts/tests/check-identity-os-rng-boundary.sh

if [[ "$static_only" == true ]]; then
  exit 0
fi

feature_sets=(
  'core|'
  'os-rng|os-rng'
  'fs-store|fs-store'
  'net|net'
  'provider-store|provider-store'
  'fs-store+net|fs-store,net'
  'fs-store+provider-store|fs-store,provider-store'
  'net+provider-store|net,provider-store'
  'fs-store+net+provider-store|fs-store,net,provider-store'
)

for feature_set in "${feature_sets[@]}"; do
  label=${feature_set%%|*}
  features=${feature_set#*|}
  check_args=(
    "+$identity_toolchain"
    check
    --locked
    -p krikos-identity
    --lib
    --no-default-features
  )
  if [[ -n "$features" ]]; then
    check_args+=(--features "$features")
  fi
  printf 'checking krikos-identity feature set: %s\n' "$label"
  CARGO_INCREMENTAL=0 cargo "${check_args[@]}"
done

printf '%s\n' 'checking krikos-identity feature set: all-features'
CARGO_INCREMENTAL=0 cargo \
  "+$identity_toolchain" check --locked -p krikos-identity --lib --all-features

tree_output=$(mktemp)
trap 'rm -f "$tree_output"' EXIT
cargo "+$identity_toolchain" tree \
  --locked \
  -p krikos-identity \
  --no-default-features \
  --target all \
  --edges normal \
  --prefix none \
  --format '{p}' >"$tree_output"

python3 - "$tree_output" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path


tree_path = Path(sys.argv[1])
package_names = {
    line.split(maxsplit=1)[0]
    for line in tree_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
}

forbidden = {"krikos", "tokio", "redb", "rand", "getrandom"}
present_forbidden = sorted(package_names.intersection(forbidden))
if present_forbidden:
    raise SystemExit(
        "no-default identity normal dependency tree contains forbidden packages: "
        + ", ".join(present_forbidden)
    )

if "krikos-base" not in package_names:
    raise SystemExit(
        "no-default identity normal dependency tree is missing required krikos-base"
    )

internal_packages = sorted(
    name
    for name in package_names
    if name == "krikos" or name.startswith("krikos-")
)
if internal_packages != ["krikos-base", "krikos-identity"]:
    raise SystemExit(
        "no-default identity normal dependency tree contains unexpected internal packages: "
        + ", ".join(internal_packages)
    )

print("identity no-default normal dependency isolation passed")
PY

printf '%s\n' 'identity Rust 1.91 feature matrix passed'
