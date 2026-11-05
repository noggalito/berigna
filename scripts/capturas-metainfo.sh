#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Capturas para la metainfo de AppStream (inventario visual §10): datos ficticios, sin red
# y con la tarjeta simulada, bajo Xvfb para que no aparezcan ventanas en el escritorio.
# Genera build/capturas/berigna-firma.png y berigna-verificacion.png.
set -eu
cd "$(git rev-parse --show-toplevel)"
PY=${PYTHON:-.venv/bin}
[ -d build/meson ] || meson setup build/meson
meson compile -C build/meson
scripts/traducciones.sh compilar
env -u WAYLAND_DISPLAY GDK_BACKEND=x11 BERIGNA_LOCALEDIR="$PWD/build/locale" \
    xvfb-run --auto-servernum "$PY/python" scripts/capturas-metainfo.py
