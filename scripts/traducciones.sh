#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Translation catalogues (ADR-0011, ADR-0015). Needs GNU gettext (Debian package "gettext").
#
#   scripts/traducciones.sh actualizar   regenerate po/berigna.pot and merge it into po/*.po
#   scripts/traducciones.sh compilar     compile po/*.po into build/locale (quz also as quy, qu)
#   scripts/traducciones.sh estado       statistics per catalogue
set -eu
cd "$(git rev-parse --show-toplevel)"
DOMAIN=berigna
LINGUAS=$(grep -v '^#' po/LINGUAS)

update() {
    grep -v '^#' po/POTFILES | grep '\.py$' | xgettext --files-from=- --language=Python \
        --from-code=UTF-8 --keyword=N_ --keyword=_ --add-comments=Translators: --sort-by-file \
        --package-name=berigna --msgid-bugs-address=https://github.com/noggalito/berigna/issues \
        --copyright-holder="noggalito" --output=po/$DOMAIN.pot
    # Blueprint views: _("…") and C_("context", "…") read as C.
    grep -v '^#' po/POTFILES | grep '\.blp$' | xgettext --files-from=- --language=C \
        --from-code=UTF-8 --keyword=_ --keyword=C_:1c,2 --add-comments=Translators: \
        --sort-by-file --join-existing --output=po/$DOMAIN.pot
    # Desktop entry: Name, GenericName, Comment and Keywords.
    grep -v '^#' po/POTFILES | grep '\.desktop\.in$' | xgettext --files-from=- --language=Desktop \
        --from-code=UTF-8 --sort-by-file --join-existing --output=po/$DOMAIN.pot
    for lang in $LINGUAS; do
        if [ -f "po/$lang.po" ]; then
            msgmerge --quiet --update --backup=none --no-fuzzy-matching "po/$lang.po" po/$DOMAIN.pot
        else
            msginit --no-translator --locale="$lang.UTF-8" --input=po/$DOMAIN.pot --output-file="po/$lang.po"
        fi
    done
}

compile() {
    for lang in $LINGUAS; do
        names=$lang
        [ "$lang" = quz ] && names="quz quy qu"  # any Southern Quechua setting finds it (ADR-0015)
        for name in $names; do
            mkdir -p "build/locale/$name/LC_MESSAGES"
            msgfmt --check --output-file="build/locale/$name/LC_MESSAGES/$DOMAIN.mo" "po/$lang.po"
        done
    done
}

case "${1:-}" in
    actualizar) update ;;
    compilar) compile ;;
    estado) for lang in $LINGUAS; do printf '%s: ' "$lang"; msgfmt --statistics -o /dev/null "po/$lang.po"; done ;;
    *) echo "uso: $0 actualizar|compilar|estado" >&2; exit 2 ;;
esac
