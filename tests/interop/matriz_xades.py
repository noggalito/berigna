# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""XAdES matrix by packaging and level for external validation (Phase 4, PR-XAD-01 to 12).

Signs one test XML document per packaging (enveloped, enveloping, detached .xsig) and level
(B-B to B-LTA) with berigna's own code, a simulated DNIe, the test PKI and a test TSA. The
output folder gets the signed document (datos.xml) and the test root, so that
tests/interop/matriz_dss.sh (DSS 6.2) can validate them; a detached signature (.xsig) is
validated against datos.xml. berigna's own XAdES verification arrives with increment 5.

    .venv/bin/python tests/interop/matriz_xades.py /tmp/matriz
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from berigna.core.formats.common import SignatureLevel
from berigna.core.formats.xades import XadesPackaging, sign_xades
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import signing_validation_context
from support.cards import make_card
from support.pki import build_pki
from support.tsa import make_timestamper

CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><Texto>Documento XML de prueba de berigna (matriz XAdES)</Texto></Declaracion>"
)
FILENAMES = {
    XadesPackaging.ENVELOPED: "xades-envuelta-{level}.xml",
    XadesPackaging.ENVELOPING: "xades-envolvente-{level}.xml",
    XadesPackaging.DETACHED: "xades-separada-{level}.xsig",
}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    pki = build_pki()
    (out / "raiz-pruebas.pem").write_bytes(pki.root.public_bytes(serialization.Encoding.PEM))
    (out / "datos.xml").write_bytes(CONTENT)
    print("| Archivo | Nivel pedido | Nivel alcanzado |")
    print("|---|---|---|")
    for packaging in XadesPackaging:
        for level in SignatureLevel:
            card, leaf = make_card(pki, f"FIRMANTE XADES {level.value}")
            stamper, tsa = make_timestamper(pki)
            context = signing_validation_context(
                pki.store,
                online=False,
                ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
                crls=[pki.arl()],
            )
            with DnieV2Token(card) as token:
                token.verify_pin(Pin("123456"))  # simulated card: no real PIN involved
                result = sign_xades(
                    CONTENT,
                    token,
                    (pki.root, pki.ca, leaf),
                    packaging=packaging,
                    level=level,
                    reference_uri="datos.xml",
                    timestamper=None if level is SignatureLevel.B_B else stamper,
                    validation_context=context,
                )
            name = FILENAMES[packaging].format(level=level.value)
            (out / name).write_bytes(result.data)
            print(f"| {name} | {level.value} | {result.level.value} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
