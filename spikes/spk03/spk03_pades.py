# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Prototipo de investigación (spike). No es código de producción.
"""SPK-03 (complement): PAdES B-B / B-T / B-LT / B-LTA with pyHanko 0.25.1 and the token-like signer."""
import io
import sys
from pathlib import Path

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko_certvalidator import ValidationContext

from spk03_common import TokenLike, TokenSigner, load_cert, test_tsa



def minimal_pdf() -> bytes:
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
            b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>"]
    text = b"BT /F1 14 Tf 72 770 Td (Documento PDF de prueba SPK-03 berigna) Tj ET"
    objs.append(b"<< /Length %d >>\nstream\n" % len(text) + text + b"\nendstream")
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + o + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref))
    return out.getvalue()


if __name__ == "__main__":
    PKI, OUT = Path(sys.argv[1]), Path(sys.argv[2])
    OUT.mkdir(parents=True, exist_ok=True)
    root, inter, signer_cert = (load_cert(PKI / f"{n}.pem") for n in ("root", "int", "signer"))
    token = TokenLike((PKI / "signer.key.der").read_bytes())
    signer = TokenSigner(token, signer_cert, [inter, root])
    tsa = test_tsa(PKI)
    src = minimal_pdf()
    (OUT / "documento.pdf").write_bytes(src)

    for level in ("B-B", "B-T", "B-LT", "B-LTA"):
        meta = signers.PdfSignatureMetadata(
            field_name="FirmaBerigna", md_algorithm="sha256", subfilter=SigSeedSubFilter.PADES,
            reason="Prueba SPK-03", location="Lima, Peru",
            embed_validation_info=level in ("B-LT", "B-LTA"),
            use_pades_lta=level == "B-LTA",
            validation_context=ValidationContext(trust_roots=[root], allow_fetching=True)
            if level in ("B-LT", "B-LTA") else None)
        out = signers.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(src)), meta, signer=signer,
                               timestamper=tsa if level != "B-B" else None)
        (OUT / f"pades-{level}.pdf").write_bytes(out.getvalue())
    print(f"PAdES generadas en {OUT}; operaciones en el 'token': {token.calls}")
