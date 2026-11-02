# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""XAdES matrix by packaging and level for external validation (Phase 4, PR-XAD-01 to 12).

Signs one test XML document per packaging (enveloped, enveloping, detached .xsig) and level
(B-B to B-LTA) with berigna's own code, a simulated DNIe, the test PKI and a test TSA. The
output folder gets the signed document (datos.xml) and the test root, so that
tests/interop/matriz_dss.sh (DSS 6.2) can validate them; a detached signature (.xsig) is
validated against the document it names. Each file is also verified offline by berigna's
own ``verify_xades`` (increment 5, RF-052): the last column, to compare with DSS.

The "difficult documents" of the review of 2026-11-01 are signed too, as BRG-CAL-006 §3.3
asks: comments inside and outside the root, ``xml:lang`` on the root (2026-11-02),
ISO-8859-1, a name with spaces and tildes (percent-encoded in the URI), and a detached
signature over a document that already carries one. A document with a processing instruction
outside the root goes in the two forms that cover it: enveloped with an Id on the root, and
enveloping (the enveloped and detached forms are refused with ERR-313).

    .venv/bin/python tests/interop/matriz_xades.py /tmp/matriz
"""

import sys
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from berigna.core.formats.common import SignatureLevel
from berigna.core.formats.xades import XadesPackaging, sign_xades
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import signing_validation_context
from berigna.core.validation.xades import verify_xades
from support.cards import make_card
from support.pki import build_pki
from support.tsa import make_timestamper

CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><Texto>Documento XML de prueba de berigna (matriz XAdES)</Texto></Declaracion>"
)
DIFFICULT = (
    '<?xml version="1.0" encoding="ISO-8859-1"?>'
    "<!-- comentario de fuera -->"
    '<Declaracion texto="café" xml:lang="es-PE"><!-- nota de dentro -->'
    "<Texto>acta de sesión de ñandú (matriz XAdES)</Texto></Declaracion>"
    "<!-- final -->"
).encode("ISO-8859-1")
DIFFICULT_NAME = "acta de sesión.xml"
WITH_PI = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<?xml-stylesheet type="text/xsl" href="estilo.xsl"?>'
    '<Declaracion Id="documento"><Texto>matriz XAdES con instrucción</Texto></Declaracion>'
)
FIRST = "xades-dificil-envuelta-B-B.xml"  # what the over-signed cases travel with
FILENAMES = {
    XadesPackaging.ENVELOPED: "xades-envuelta-{level}.xml",
    XadesPackaging.ENVELOPING: "xades-envolvente-{level}.xml",
    XadesPackaging.DETACHED: "xades-separada-{level}.xsig",
}
DIFFICULT_FILENAMES = {
    XadesPackaging.ENVELOPED: "xades-dificil-envuelta-{level}.xml",
    XadesPackaging.ENVELOPING: "xades-dificil-envolvente-{level}.xml",
    XadesPackaging.DETACHED: "xades-dificil-separada-{level}.xsig",
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
    (out / DIFFICULT_NAME).write_bytes(DIFFICULT)
    print("| Archivo | Nivel pedido | Nivel alcanzado | verify_xades |")
    print("|---|---|---|---|")

    def matrix(
        content: bytes, name: str, packaging: XadesPackaging, template: str, level: SignatureLevel
    ) -> None:
        """Sign ``content`` at ``level``, detached under ``name``, as ``template`` says."""
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
                content,
                token,
                (pki.root, pki.ca, leaf),
                packaging=packaging,
                level=level,
                reference_uri=quote(name) if packaging is XadesPackaging.DETACHED else None,
                timestamper=None if level is SignatureLevel.B_B else stamper,
                validation_context=context,
            )
        written = template.format(level=level.value)
        (out / written).write_bytes(result.data)
        detached = content if packaging is XadesPackaging.DETACHED else None
        [report] = verify_xades(result.data, pki.store, content=detached, online=False).signatures
        verified = f"{report.indication.name}/{report.subindication or '-'}"
        stamps = [report.timestamp] if report.timestamp else []
        stamps += list(report.archive_timestamps)
        if stamps:
            verified += " (sellos: " + ", ".join(s.indication.name for s in stamps) + ")"
        print(f"| {written} | {level.value} | {result.level.value} | {verified} |")

    cases = [
        *((packaging, FILENAMES[packaging], CONTENT, "datos.xml") for packaging in XadesPackaging),
        *(
            (packaging, DIFFICULT_FILENAMES[packaging], DIFFICULT, DIFFICULT_NAME)
            for packaging in XadesPackaging
        ),
    ]
    for packaging, template, content, name in cases:
        for level in SignatureLevel:
            matrix(content, name, packaging, template, level)
    # a document with an instruction outside the root, in the two forms that cover it
    for packaging, template in (
        (XadesPackaging.ENVELOPED, "xades-con-pi-envuelta-{level}.xml"),
        (XadesPackaging.ENVELOPING, "xades-con-pi-envolvente-{level}.xml"),
    ):
        for level in SignatureLevel:
            matrix(WITH_PI.encode(), "datos.xml", packaging, template, level)
    # a document that already carries a signature: detached, which does not touch it
    already = (out / FIRST).read_bytes()
    for level in SignatureLevel:
        matrix(
            already,
            FIRST,
            XadesPackaging.DETACHED,
            "xades-separada-sobre-firma-{level}.xsig",
            level,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
