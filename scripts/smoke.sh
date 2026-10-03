#!/usr/bin/env bash
# Demo-path smoke test. Run before every merge to main. main is never broken.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run pytest -m smoke -q
