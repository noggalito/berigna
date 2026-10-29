# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Prototipo de investigación (spike). No es código de producción.
"""Extract signer / TSA info from signatures embedded in a (public) PDF. Read-only parsing."""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()
sigs = re.findall(rb"/Contents\s*<([0-9A-Fa-f]{200,})>", data)
subfilters = sorted(set(re.findall(rb"/SubFilter\s*/([A-Za-z0-9.]+)", data)))
print(f"firmas: {len(sigs)}  subfilters: {[s.decode() for s in subfilters]}")
for i, hx in enumerate(sigs, 1):
    der = bytes.fromhex(hx.decode()).rstrip(b"\x00")
    with tempfile.NamedTemporaryFile(suffix=".p7s") as f:
        f.write(der); f.flush()
        out = subprocess.run(["openssl", "cms", "-inform", "DER", "-in", f.name, "-cmsout", "-print"],
                             capture_output=True, text=True).stdout
    print(f"--- firma {i}: {len(der)} B")
    has_ts = "id-smime-aa-timeStampToken" in out
    print("  sello de tiempo de firma (B-T):", has_ts)
    for line in out.splitlines():
        s = line.strip()
        if s.startswith(("issuer:", "subject:")) or "CN=" in s and ("TSA" in s.upper() or "TIME" in s.upper() or "SELL" in s.upper()):
            print("  ", s[:160])
    for m in sorted(set(re.findall(r"(https?://[^\s'\"]+)", out))):
        print("   url:", m)
print("DSS en PDF:", b"/DSS" in data, " DocTimeStamp:", b"ETSI.RFC3161" in data)
