# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Other small PDFs for the tests."""

import io

from reportlab.pdfgen import canvas


def two_page_pdf() -> bytes:
    out = io.BytesIO()
    pdf = canvas.Canvas(out, invariant=True)
    for number in (1, 2):
        pdf.drawString(72, 720, f"Página {number}")
        pdf.showPage()
    pdf.save()
    return out.getvalue()


def pdf_with_freed_info() -> bytes:
    """A PDF whose /Info was freed by a later update without removing the trailer entry, as
    ExifTool leaves it after deleting the metadata (a real document, 2026-10-28)."""
    from support.pki import minimal_pdf

    base = minimal_pdf()
    start = base.rfind(b"\nxref\n") + 1
    offsets = [int(line[:10]) for line in base[start:].splitlines()[3:7]]
    out = io.BytesIO()
    out.write(base[:start])
    info = out.tell()
    out.write(b"5 0 obj\n<< /Title (Documento) /Producer (Prueba) >>\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in [*offsets, info]:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(b"trailer\n<< /Size 6 /Root 1 0 R /Info 5 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref)
    # The metadata cleaner's update: object 5 freed, /Info left out of the new trailer.
    update = out.tell()
    out.write(b"xref\n0 1\n0000000005 65535 f \n5 1\n0000000000 00001 f \n")
    out.write(
        b"trailer\n<< /Size 6 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (xref, update)
    )
    return out.getvalue()
