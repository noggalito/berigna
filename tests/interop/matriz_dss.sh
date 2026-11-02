#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Validate the files of tests/interop/matriz_pades.py, matriz_cades.py and matriz_xades.py
# with DSS 6.2 (external validator). A detached CAdES (.p7s) is validated against datos.txt,
# a detached XAdES (.xsig) against the document it names: datos.xml, the "acta de sesión.xml"
# of the difficult documents, or the enveloped signature it follows (review of 2026-11-01).
# Needs the DSS harness of SPK-03 built (spike/preparar-entorno.sh; spikes/spk03/dssval).
#   tests/interop/matriz_dss.sh /tmp/matriz [ruta/al/dssval]
set -eu
OUT=$(readlink -f "$1")
DSSVAL=$(readlink -f "${2:-spikes/spk03/dssval}")
cd "$DSSVAL"
echo "| Archivo | DSS 6.2 |"
echo "|---|---|"
for f in "$OUT"/pades-*.pdf "$OUT"/cades-*.p7s "$OUT"/cades-*.p7m \
    "$OUT"/xades-envuelta-*.xml "$OUT"/xades-envolvente-*.xml "$OUT"/xades-separada-*.xsig \
    "$OUT"/xades-dificil-*.xml "$OUT"/xades-dificil-*.xsig "$OUT"/xades-con-pi-*.xml; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    detached=""
    case "$f" in
        *.p7s) detached="$OUT/datos.txt" ;;
        *.xsig)
            case "$b" in
                xades-dificil-separada-*) detached="$OUT/acta de sesión.xml" ;;
                xades-separada-sobre-firma-*) detached="$OUT/xades-dificil-envuelta-B-B.xml" ;;
                *) detached="$OUT/datos.xml" ;;
            esac ;;
    esac
    # quoted, because "acta de sesión.xml" has spaces; empty means no detached document
    if [ -n "$detached" ]; then
        line=$(java -cp "classes:lib/*" brg.Validate "$f" "$OUT/raiz-pruebas.pem" "$OUT/dss-$b" "$detached" \
            2>/dev/null | head -1 | sed 's/^S-[0-9A-F]* | //')
    else
        line=$(java -cp "classes:lib/*" brg.Validate "$f" "$OUT/raiz-pruebas.pem" "$OUT/dss-$b" \
            2>/dev/null | head -1 | sed 's/^S-[0-9A-F]* | //')
    fi
    echo "| $b | $line |"
done
