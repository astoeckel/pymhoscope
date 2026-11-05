#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "$SCRIPT_DIR"

uv run ruff check --select I --fix --quiet
uv run ruff format --quiet
uv run ruff check
uv run ty check
