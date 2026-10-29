#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Desktop integration of the source tree, for development: the desktop entry and the icons in
# ~/.local/share, so that GNOME shows berigna's icon and name in the dock and the overview
# while it runs from scripts/ejecutar.sh. The installed package (.deb) does not need it.
#   scripts/escritorio.sh           install (again, after changing the icons)
#   scripts/escritorio.sh quitar    remove
set -eu
cd "$(dirname "$0")/.."
ID=com.noggalito.Berigna
OLD_ID=pe.berigna.Berigna  # identifier before ADR-0019
DATA=${XDG_DATA_HOME:-$HOME/.local/share}
ENTRY="$DATA/applications/$ID.desktop"
ICONS="$DATA/icons/hicolor"

remove() {
    rm -f "$DATA/applications/$1.desktop" "$ICONS/scalable/apps/$1.svg" \
        "$ICONS/symbolic/apps/$1-symbolic.svg"
    for size in 16x16 24x24 32x32; do rm -f "$ICONS/$size/apps/$1.svg"; done
}
remove "$OLD_ID"

if [ "${1:-}" = quitar ]; then
    remove "$ID"
    echo "Quitada la integración con el escritorio."
    exit 0
fi
[ -d build/meson ] || meson setup build/meson > /dev/null
meson compile -C build/meson > /dev/null
mkdir -p "$DATA/applications" "$ICONS/scalable/apps" "$ICONS/symbolic/apps"
install -m 644 "data/icons/$ID.svg" "$ICONS/scalable/apps/$ID.svg"
install -m 644 "data/icons/$ID-symbolic.svg" "$ICONS/symbolic/apps/$ID-symbolic.svg"
for size in 16x16 24x24 32x32; do
    mkdir -p "$ICONS/$size/apps"
    install -m 644 "data/icons/$ID-small.svg" "$ICONS/$size/apps/$ID.svg"
done
# The built entry, started from this tree and marked as such.
sed -e "s|^Exec=.*|Exec=$PWD/scripts/ejecutar.sh %F|" \
    -e "s|^\(Name\(\[[^]]*\]\)\{0,1\}\)=berigna$|\1=berigna (desarrollo)|" \
    "build/meson/data/$ID.desktop" > "$ENTRY"
touch "$ICONS"  # GNOME rereads the icon theme
command -v update-desktop-database > /dev/null && update-desktop-database "$DATA/applications" || true
echo "Integración instalada: $ENTRY"
