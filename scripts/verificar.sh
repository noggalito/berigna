#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
# Local quality gate: the same checks the CI runs. Never runs HIL tests (no card, no PIN).
# Optional pre-push hook:  ln -s ../../scripts/verificar.sh .git/hooks/pre-push
set -eu
cd "$(git rev-parse --show-toplevel)"
PY=${PYTHON:-.venv/bin}
"$PY/ruff" format --check src tests
"$PY/ruff" check src tests
"$PY/mypy"
scripts/traducciones.sh compilar
# Views and settings schema of the interface (ADR-0010); the tests read them from build/meson.
[ -d build/meson ] || meson setup build/meson
meson compile -C build/meson
# The interface tests need a display: Xvfb, so that they also run without a desktop.
env -u BERIGNA_HIL BERIGNA_LOCALEDIR="$PWD/build/locale" \
    xvfb-run --auto-servernum "$PY/pytest" -q --cov=berigna
