#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
metadata=$(mktemp)
sim_metadata=$(mktemp)
trap 'rm -f "$metadata" "$sim_metadata"' EXIT

(cd "$repo_root" && cargo metadata --no-deps --format-version 1 >"$metadata")
(cd "$repo_root" && cargo metadata --manifest-path krikos-sim/Cargo.toml --no-deps --format-version 1 >"$sim_metadata")

python3 "$repo_root/scripts/check_workspace_architecture.py" \
  --policy "$repo_root/scripts/workspace-architecture.toml" \
  --root-metadata "$metadata" \
  --sim-metadata "$sim_metadata" \
  --repo-root "$repo_root"

python3 - "$repo_root" "$metadata" "$sim_metadata" <<'PY'
import json
from pathlib import Path
import re
import sys
import tomllib

root = Path(sys.argv[1])
metadata = json.loads(Path(sys.argv[2]).read_text())
sim_metadata = json.loads(Path(sys.argv[3]).read_text())
failures: list[str] = []


def load(path: Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def fail(message: str) -> None:
    failures.append(message)


root_manifest = load(root / "Cargo.toml")
workspace = root_manifest.get("workspace", {})
expected_package = {
    "version": "1.0.0",
    "edition": "2024",
    "rust-version": "1.91",
    "license": "MIT OR Apache-2.0",
    "repository": "https://github.com/holon-technologies/iroh",
}
actual_package = workspace.get("package", {})
for key, expected in expected_package.items():
    if actual_package.get(key) != expected:
        fail(f"[workspace.package].{key} must be {expected!r}")

members = set(workspace.get("members", []))
excluded = set(workspace.get("exclude", []))
for required in {"krikos-base", "krikos-dns", "krikos-dns-server", "krikos-relay", "krikos-runtime", "krikos", "krikos/bench", "tools/determinism-checker"}:
    if required not in members:
        fail(f"root workspace member missing: {required}")
for required in {"krikos-sim", "fuzz", "compat/relay-v1-interop"}:
    if required not in excluded:
        fail(f"root workspace exclusion missing: {required}")

publishable = [
    "krikos-base",
    "krikos-resolver",
    "krikos-dns",
    "krikos-dns-server",
    "krikos-relay",
    "krikos-runtime",
    "krikos",
]
if "krikos-resolver" not in members:
    fail("root workspace member missing: krikos-resolver")

for package in publishable:
    manifest_path = root / package / "Cargo.toml"
    if not manifest_path.is_file():
        fail(f"publishable package manifest missing: {package}/Cargo.toml")
        continue
    manifest = load(manifest_path)
    table = manifest.get("package", {})
    for key in expected_package:
        if table.get(key) != {"workspace": True}:
            fail(f"{package}/Cargo.toml must inherit package.{key} from the workspace")

for package in ["krikos/bench", "tools/determinism-checker"]:
    manifest = load(root / package / "Cargo.toml")
    table = manifest.get("package", {})
    for key in ["edition", "rust-version", "license"]:
        if table.get(key) != {"workspace": True}:
            fail(f"{package}/Cargo.toml must inherit package.{key} from the workspace")

workspace_dependencies = workspace.get("dependencies", {})
for package in publishable:
    dependency = workspace_dependencies.get(package)
    if not isinstance(dependency, dict):
        fail(f"[workspace.dependencies] missing {package}")
        continue
    if dependency.get("version") != "1.0.0" or "path" not in dependency:
        fail(f"workspace dependency {package} must own its 1.0.0 path/version pair")

sim_manifest = load(root / "krikos-sim" / "Cargo.toml")
sim_package = sim_manifest.get("package", {})
for key, expected in expected_package.items():
    if sim_package.get(key) != expected:
        fail(f"krikos-sim package.{key} must mirror root workspace value {expected!r}")

fuzz_patch = load(root / "fuzz" / "Cargo.toml").get("patch", {}).get("crates-io", {})
if "rustls" in fuzz_patch:
    fail("fuzz workspace must use production Rustls; deterministic Rustls is simulator-only")
sim_patch = sim_manifest.get("patch", {}).get("crates-io", {})
rustls_patch = sim_patch.get("rustls", {})
if rustls_patch.get("path") != "../vendor/rustls-0.23.41":
    fail("krikos-sim must own the sole deterministic Rustls path patch")
if "rustls" in root_manifest.get("patch", {}).get("crates-io", {}):
    fail("production root workspace must not patch Rustls")

packages = {package["name"]: package for package in metadata["packages"]}
workspace_names = set(packages)
first_party = {name for name in workspace_names if name.startswith("krikos") or name == "determinism-checker"}

resolver_forbidden = {"krikos-base", "krikos-dns", "simple-dns", "mainline"}
resolver_dependencies = {
    dependency["name"] for dependency in packages.get("krikos-resolver", {}).get("dependencies", [])
}
if forbidden := resolver_dependencies & resolver_forbidden:
    fail(f"krikos-resolver contains endpoint-aware dependencies: {sorted(forbidden)}")

endpoint_facade = (root / "krikos" / "src" / "endpoint.rs").read_text()
endpoint_source = "\n".join(
    [
        endpoint_facade,
        (root / "krikos" / "src" / "endpoint" / "builder.rs").read_text(),
    ]
)
if "pub fn simulation_environment_for_test(" not in endpoint_source:
    fail("endpoint builder must expose the single simulation environment entry point")
for forbidden_setter in [
    "pub fn runtime_context_for_test(",
    "pub fn ip_socket_factory_for_test(",
    "pub fn network_monitor_for_test(",
    "pub fn simulation_crypto_for_test(",
]:
    if forbidden_setter in endpoint_source:
        fail(f"endpoint builder exposes forbidden partial simulation setter: {forbidden_setter}")

endpoint_dir = root / "krikos" / "src" / "endpoint"
for module in ["builder.rs", "handle.rs", "lifecycle.rs", "relay_status.rs", "tests.rs"]:
    if not (endpoint_dir / module).is_file():
        fail(f"endpoint responsibility module missing: krikos/src/endpoint/{module}")
if len(endpoint_facade.splitlines()) > 600:
    fail("krikos/src/endpoint.rs must remain a narrow facade (maximum 600 lines)")

socket_dir = root / "krikos" / "src" / "socket"
for module in ["config.rs", "inner.rs", "actor.rs", "direct_addr.rs"]:
    if not (socket_dir / module).is_file():
        fail(f"socket responsibility module missing: krikos/src/socket/{module}")
socket_facade = (root / "krikos" / "src" / "socket.rs").read_text()
if len(socket_facade.splitlines()) > 800:
    fail("krikos/src/socket.rs must remain a narrow facade (maximum 800 lines)")

relay_actor_dir = socket_dir / "transports" / "relay" / "actor"
for module in ["mod.rs", "session.rs", "connect.rs", "messages.rs", "tests.rs"]:
    if not (relay_actor_dir / module).is_file():
        fail(f"relay actor responsibility module missing: {module}")
if (socket_dir / "transports" / "relay" / "actor.rs").exists():
    fail("relay actor must use a directory facade instead of actor.rs")
relay_actor_facade = (relay_actor_dir / "mod.rs").read_text() if relay_actor_dir.is_dir() else ""
if relay_actor_facade and len(relay_actor_facade.splitlines()) > 800:
    fail("relay actor facade must remain focused (maximum 800 lines)")

relay_server_dir = root / "krikos-relay" / "src" / "server"
for module in ["config.rs", "certs.rs", "limits.rs", "supervisor.rs", "routes.rs"]:
    if not (relay_server_dir / module).is_file():
        fail(f"relay server responsibility module missing: krikos-relay/src/server/{module}")
relay_server_facade = (root / "krikos-relay" / "src" / "server.rs").read_text()
if len(relay_server_facade.splitlines()) > 600:
    fail("krikos-relay/src/server.rs must remain a narrow facade (maximum 600 lines)")

http_server_dir = relay_server_dir / "http_server"
for module in ["mod.rs", "listener.rs", "upgrade.rs", "connection.rs", "service.rs", "tests.rs"]:
    if not (http_server_dir / module).is_file():
        fail(f"relay HTTP responsibility module missing: {module}")
if (relay_server_dir / "http_server.rs").exists():
    fail("relay HTTP server must use a directory facade instead of http_server.rs")
http_server_facade = (http_server_dir / "mod.rs").read_text() if http_server_dir.is_dir() else ""
if http_server_facade and len(http_server_facade.splitlines()) > 700:
    fail("relay HTTP server facade must remain focused (maximum 700 lines)")

sim_src = root / "krikos-sim" / "src"
for module in ["engine.rs", "model.rs", "execution.rs", "evidence.rs", "operations_api.rs"]:
    if not (sim_src / module).is_file():
        fail(f"simulator domain facade missing: krikos-sim/src/{module}")
sim_lib = (sim_src / "lib.rs").read_text()
for domain in ["engine", "model", "execution", "evidence", "operations", "cli"]:
    if f"pub mod {domain};" not in sim_lib:
        fail(f"simulator public domain missing: {domain}")
if re.search(r"(?m)^pub use ", sim_lib):
    fail("krikos-sim must not expose flat root reexports after the architecture cut")

for directory, modules, maximum in [
    (
        "cli",
        ["mod.rs", "run.rs", "replay.rs", "campaign.rs", "soak.rs", "parity.rs", "corpus.rs", "gate.rs", "shared.rs"],
        900,
    ),
    (
        "runner",
        ["mod.rs", "reference.rs", "backend.rs", "orchestration.rs", "report.rs", "error.rs"],
        900,
    ),
    (
        "scenario_model",
        ["mod.rs", "schema.rs", "migration.rs", "validation.rs", "builder.rs", "generator.rs"],
        900,
    ),
]:
    module_dir = sim_src / directory
    for module in modules:
        if not (module_dir / module).is_file():
            fail(f"simulator {directory} responsibility module missing: {module}")
    if (sim_src / f"{directory}.rs").exists():
        fail(f"simulator {directory} must use a directory facade")
    facade = (module_dir / "mod.rs").read_text() if module_dir.is_dir() else ""
    if facade and len(facade.splitlines()) > maximum:
        fail(f"simulator {directory} facade exceeds {maximum} lines")

dns_server = root / "krikos-dns-server"
dns_server_lib = (dns_server / "src" / "lib.rs").read_text()
if re.search(r"(?s)#\[cfg\(test\)\]\s*mod tests", dns_server_lib):
    fail("krikos-dns-server crate root must not own implementation or integration tests")
for test in ["publish_resolve.rs", "smoke.rs", "mainline.rs"]:
    if not (dns_server / "tests" / test).is_file():
        fail(f"krikos-dns-server package-boundary test missing: {test}")
dns_store = (dns_server / "src" / "store.rs").read_text()
if "async fn store_eviction" not in dns_store:
    fail("krikos-dns-server store eviction must remain a private store unit test")

for leaf in ["krikos-base", "krikos-runtime", "krikos-resolver"]:
    if leaf not in packages:
        continue
    outgoing = {
        dependency["name"]
        for dependency in packages[leaf]["dependencies"]
        if dependency.get("kind") in (None, "normal") and dependency["name"] in first_party
    }
    if outgoing:
        fail(f"first-party leaf {leaf} has outgoing edges: {sorted(outgoing)}")

for package in packages.values():
    for dependency in package["dependencies"]:
        path = dependency.get("path") or ""
        if "krikos-sim" in path:
            fail(f"production package {package['name']} depends on krikos-sim")

sim_names = {package["name"] for package in sim_metadata["packages"]}
if sim_names != {"krikos-sim"}:
    fail(f"simulator workspace must contain only krikos-sim, found {sorted(sim_names)}")

if failures:
    for failure in failures:
        print(f"workspace architecture contract: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("workspace architecture contract passed")
PY
