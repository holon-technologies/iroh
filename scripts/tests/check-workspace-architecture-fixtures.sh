#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/tests/workspace_policy_fixtures.py"
