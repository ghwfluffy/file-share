#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
python_bin="python"
if [[ -x .venv/bin/python ]]; then
  python_bin=".venv/bin/python"
fi
"${python_bin}" -m pytest
