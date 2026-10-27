#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPK-03: validate every generated signature with DSS 6.2 and print a matrix row per file.
S=$(dirname "$(readlink -f "$0")")
cd "$S/dssval" || exit 1
for f in "$S"/out/cades/cades-* "$S"/out/xades/xades-* "$S"/out/pades/pades-*; do
  b=$(basename "$f")
  case $b in *.p7s) extra="$S/out/cades/datos.txt" ;; *) extra="" ;; esac
  line=$(java -cp "classes:lib/*" brg.Validate "$f" "$S/pki/root.pem" "$S/reportes/$b" $extra 2>/dev/null | head -1 | sed 's/^S-[0-9A-F]* | //')
  ts=$(python3 -I - "$S/reportes/$b/detailed-report.xml" <<'EOF'
import sys, xml.etree.ElementTree as ET
r = ET.parse(sys.argv[1]).getroot(); ln = lambda e: e.tag.split('}')[-1]
print(" ".join(f"{e.get('Type')}={[x.text for x in e.iter() if ln(x)=='Indication'][-1]}"
               for e in r.iter() if ln(e) == "ValidationProcessBasicTimestamp") or "-")
EOF
)
  printf '%-28s | %s | %s\n' "$b" "$line" "$ts"
done
