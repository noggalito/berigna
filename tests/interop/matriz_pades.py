# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""PAdES-by-level matrix for external validation (Phase 2 exit criterion, PR-INT-*).

Signs one test PDF per level (B-B, B-T, B-LT, B-LTA) with berigna's own code, a simulated
DNIe, the test PKI and a test TSA, and verifies each one with berigna as it stands, with only
what the document carries. The output folder also gets the test root, so that an external
validator (tests/interop/matriz_dss.sh, DSS 6.2) can check the same files.

    .venv/bin/python tests/interop/matriz_pades.py /tmp/matriz
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from berigna.core.formats.pades import SignatureLevel, sign_pdf_pades
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.trust import TrustedCertificate, TrustStore
from berigna.core.validation import signing_validation_context, verify_pdf
from support.cards import make_card
from support.pki import build_pki, minimal_pdf
from support.tsa import make_timestamper


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    pki = build_pki()
    (out / "raiz-pruebas.pem").write_bytes(pki.root.public_bytes(serialization.Encoding.PEM))
    store = TrustStore([TrustedCertificate(pki.root, "root", "TEST")])
    print("| Nivel pedido | Nivel alcanzado | berigna (sin red, solo el documento) |")
    print("|---|---|---|")
    for level in SignatureLevel:
        card, leaf = make_card(pki, "FIRMANTE " + level.value)
        stamper, tsa = make_timestamper(pki)
        context = signing_validation_context(
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
            crls=[pki.arl()],
        )
        with DnieV2Token(card) as token:
            token.verify_pin(Pin("123456"))  # simulated card: no real PIN involved
            result = sign_pdf_pades(
                minimal_pdf(f"Matriz PAdES {level.value}"),
                token,
                (pki.root, pki.ca, leaf),
                level=level,
                timestamper=None if level is SignatureLevel.B_B else stamper,
                validation_context=context,
            )
        path = out / f"pades-{level.value}.pdf"
        path.write_bytes(result.data)
        [report] = verify_pdf(result.data, store, online=False).signatures
        outcome = f"{report.indication.value} / {report.subindication or '—'}"
        print(f"| {level.value} | {result.level.value} | {outcome} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
