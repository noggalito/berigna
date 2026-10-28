#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
# Run the interface from the source tree, with the views, schema and catalogues of build/.
#   scripts/ejecutar.sh [archivo…]
# Preferences go to dconf under /pe/berigna/Berigna/, as in the installed program.
set -eu
cd "$(git rev-parse --show-toplevel)"
PY=${PYTHON:-.venv/bin}
scripts/traducciones.sh compilar
[ -d build/meson ] || meson setup build/meson
meson compile -C build/meson > /dev/null
export BERIGNA_RESOURCES="$PWD/build/meson/data/berigna.gresource"
export BERIGNA_LOCALEDIR="$PWD/build/locale"
export GSETTINGS_SCHEMA_DIR="$PWD/build/meson/data"
exec "$PY/python" -m berigna "$@"
