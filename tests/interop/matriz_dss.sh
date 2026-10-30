#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Validate the files of tests/interop/matriz_pades.py and matriz_cades.py with DSS 6.2
# (external validator). A detached CAdES (.p7s) is validated against datos.txt.
# Needs the DSS harness of SPK-03 built (spikes/preparar-entorno.sh; spikes/spk03/dssval).
#   tests/interop/matriz_dss.sh /tmp/matriz [ruta/al/dssval]
set -eu
OUT=$(readlink -f "$1")
DSSVAL=$(readlink -f "${2:-spikes/spk03/dssval}")
cd "$DSSVAL"
echo "| Archivo | DSS 6.2 |"
echo "|---|---|"
for f in "$OUT"/pades-*.pdf "$OUT"/cades-*.p7s "$OUT"/cades-*.p7m; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    detached=""
    case "$f" in *.p7s) detached="$OUT/datos.txt" ;; esac
    line=$(java -cp "classes:lib/*" brg.Validate "$f" "$OUT/raiz-pruebas.pem" "$OUT/dss-$b" $detached \
        2>/dev/null | head -1 | sed 's/^S-[0-9A-F]* | //')
    echo "| $b | $line |"
done
