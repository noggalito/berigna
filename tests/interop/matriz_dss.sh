#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
# Validate the files of tests/interop/matriz_pades.py with DSS 6.2 (external validator).
# Needs the DSS harness of SPK-03 built (spikes/preparar-entorno.sh; spikes/spk03/dssval).
#   tests/interop/matriz_dss.sh /tmp/matriz [ruta/al/dssval]
set -eu
OUT=$(readlink -f "$1")
DSSVAL=$(readlink -f "${2:-spikes/spk03/dssval}")
cd "$DSSVAL"
echo "| Archivo | DSS 6.2 |"
echo "|---|---|"
for f in "$OUT"/pades-*.pdf; do
    b=$(basename "$f" .pdf)
    line=$(java -cp "classes:lib/*" brg.Validate "$f" "$OUT/raiz-pruebas.pem" "$OUT/dss-$b" 2>/dev/null \
        | head -1 | sed 's/^S-[0-9A-F]* | //')
    echo "| $b | $line |"
done
