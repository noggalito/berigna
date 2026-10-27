#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
# Local quality gate: the same checks the CI will run. Never runs HIL tests (no card, no PIN).
# Optional pre-push hook:  ln -s ../../scripts/verificar.sh .git/hooks/pre-push
set -eu
cd "$(git rev-parse --show-toplevel)"
PY=${PYTHON:-.venv/bin}
"$PY/ruff" format --check src tests
"$PY/ruff" check src tests
"$PY/mypy"
env -u BERIGNA_HIL "$PY/pytest" -q --cov=berigna
