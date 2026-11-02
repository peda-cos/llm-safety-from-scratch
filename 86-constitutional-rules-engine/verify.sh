#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v uv >/dev/null 2>&1; then
  echo "error: uv is required (https://docs.astral.sh/uv/)" >&2
  exit 1
fi

uv sync --frozen --all-groups --no-progress
uv run --frozen --no-progress python code/main.py
uv run --frozen --no-progress pytest
uv run --frozen --no-progress mypy code tests
