# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""CAdES matrix by packaging and level for external validation (Phase 4, PR-CAD-01 to 08).

Signs one test file per packaging (detached .p7s, enveloping .p7m) and level (B-B to B-LTA)
with berigna's own code, a simulated DNIe, the test PKI and a test TSA. The output folder
gets the signed file (datos.txt) and the test root, so that tests/interop/matriz_dss.sh
(DSS 6.2) can validate them. berigna's own CAdES verification arrives with increment 3.

    .venv/bin/python tests/interop/matriz_cades.py /tmp/matriz
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from berigna.core.formats.cades import CadesPackaging, sign_cades
from berigna.core.formats.common import SignatureLevel
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import signing_validation_context
from support.cards import make_card
from support.pki import build_pki
from support.tsa import make_timestamper

CONTENT = b"Documento de prueba de berigna (matriz CAdES)\n" * 40


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    pki = build_pki()
    (out / "raiz-pruebas.pem").write_bytes(pki.root.public_bytes(serialization.Encoding.PEM))
    (out / "datos.txt").write_bytes(CONTENT)
    print("| Archivo | Nivel pedido | Nivel alcanzado |")
    print("|---|---|---|")
    for packaging in CadesPackaging:
        for level in SignatureLevel:
            card, leaf = make_card(pki, f"FIRMANTE CADES {level.value}")
            stamper, tsa = make_timestamper(pki)
            context = signing_validation_context(
                pki.store,
                online=False,
                ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
                crls=[pki.arl()],
            )
            with DnieV2Token(card) as token:
                token.verify_pin(Pin("123456"))  # simulated card: no real PIN involved
                result = sign_cades(
                    CONTENT,
                    token,
                    (pki.root, pki.ca, leaf),
                    packaging=packaging,
                    level=level,
                    timestamper=None if level is SignatureLevel.B_B else stamper,
                    validation_context=context,
                )
            name = f"cades-{level.value}.{packaging.value}"
            (out / name).write_bytes(result.data)
            print(f"| {name} | {level.value} | {result.level.value} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
