#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
# Run the interface from the source tree, with the views, schema and catalogues of build/.
#   scripts/ejecutar.sh [archivo…]
# Preferences go to dconf under /pe/berigna/Berigna/, as in the installed program.
set -eu
# Files given with a relative path are found before leaving the current directory.
for file; do
    shift
    if [ -e "$file" ]; then set -- "$@" "$(realpath "$file")"; else set -- "$@" "$file"; fi
done
# From the script's own directory: the desktop entry of scripts/escritorio.sh starts it from $HOME.
cd "$(dirname "$0")/.."
PY=${PYTHON:-.venv/bin}
scripts/traducciones.sh compilar
[ -d build/meson ] || meson setup build/meson
meson compile -C build/meson > /dev/null
export BERIGNA_RESOURCES="$PWD/build/meson/data/berigna.gresource"
export BERIGNA_LOCALEDIR="$PWD/build/locale"
export GSETTINGS_SCHEMA_DIR="$PWD/build/meson/data"
exec "$PY/python" -m berigna "$@"
