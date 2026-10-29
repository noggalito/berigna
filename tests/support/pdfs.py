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
