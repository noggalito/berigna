# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Human-readable verification report as PDF (RF-054), in es_PE or Southern Quechua.

The report is built with ReportLab in invariant mode: the same verification gives the same
bytes, which suits an evidence file, as long as the berigna version and the fonts are the same.
Text uses DejaVu Sans when installed (Debian package fonts-dejavu-core, a dependency of the
berigna package) so that any character of either language is shown; Helvetica otherwise.
A Quechua report shows the es_PE text for strings still waiting for the translators and says
that the Spanish version prevails (ADR-0011 §3, ADR-0015).
"""

import gettext
import io
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import berigna
from berigna.core.i18n import Language, translations
from berigna.core.report import messages
from berigna.core.report.explanations import (
    common_name,
    display_name,
    explain_signature,
    explain_timestamp,
    format_time,
)
from berigna.core.trust import TrustStore
from berigna.core.validation import (
    Indication,
    PdfSignatureReport,
    PdfVerification,
    TimestampReport,
)

_DEJAVU = Path("/usr/share/fonts/truetype/dejavu")
_COLOURS = {
    Indication.TOTAL_PASSED: colors.HexColor("#26a269"),
    Indication.TOTAL_FAILED: colors.HexColor("#c01c28"),
    Indication.INDETERMINATE: colors.HexColor("#c64600"),
}


def _fonts(directory: Path = _DEJAVU) -> tuple[str, str]:
    regular, bold = directory / "DejaVuSans.ttf", directory / "DejaVuSans-Bold.ttf"
    if not (regular.is_file() and bold.is_file()):
        return "Helvetica", "Helvetica-Bold"
    if "DejaVuSans" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("DejaVuSans", str(regular)))
        pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(bold)))
    return "DejaVuSans", "DejaVuSans-Bold"


class _Writer:
    def __init__(self, catalogue: gettext.NullTranslations, regular: str, bold: str) -> None:
        self.t = catalogue.gettext
        self.body = ParagraphStyle("body", fontName=regular, fontSize=9.5, leading=13)
        self.small = ParagraphStyle("small", parent=self.body, fontSize=8, leading=10)
        self.title = ParagraphStyle("title", fontName=bold, fontSize=16, leading=20)
        self.heading = ParagraphStyle("heading", fontName=bold, fontSize=11.5, leading=15)
        self.label = ParagraphStyle("label", parent=self.body, fontName=bold)

    def p(self, text: str, style: ParagraphStyle | None = None) -> Paragraph:
        return Paragraph(escape(text), style or self.body)

    def table(self, rows: list[tuple[str, str]]) -> Table:
        data = [[self.p(self.t(label), self.label), self.p(value)] for label, value in rows]
        table = Table(data, colWidths=[52 * mm, None], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#c0bfbc")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        return table

    def result(self, indication: Indication) -> Paragraph:
        style = ParagraphStyle(
            f"result-{indication.name}", parent=self.label, textColor=_COLOURS[indication]
        )
        return self.p(self.t(messages.INDICATIONS[indication]), style)


def _grouped(digest: str) -> str:
    """A hex digest in groups of eight: fits the page and is easy to compare by eye."""
    return " ".join(digest[i : i + 8] for i in range(0, len(digest), 8))


def _etsi(indication: Indication, subindication: str | None) -> str:
    return indication.value + (f" / {subindication}" if subindication else "")


def _timestamp_text(w: _Writer, stamp: TimestampReport | None) -> str:
    if stamp is None:
        return w.t(messages.REPORT_NONE)
    parts = [format_time(stamp.time)] if stamp.time is not None else []
    if stamp.tsa is not None:
        parts.append(common_name(stamp.tsa))
    parts.append(_etsi(stamp.indication, stamp.subindication))
    return " · ".join(parts)


def _signature_section(
    w: _Writer, report: PdfSignatureReport, number: int, total: int, catalogue: Any
) -> list[Any]:
    rows: list[tuple[str, str]] = [
        (messages.REPORT_ETSI, _etsi(report.indication, report.subindication)),
    ]
    if report.signer is not None:
        rows += [
            (messages.REPORT_SIGNER, common_name(report.signer)),
            (messages.REPORT_ISSUER, display_name(report.signer.issuer)),
        ]
    if report.claimed_signing_time is not None:
        rows.append((messages.REPORT_CLAIMED_TIME, format_time(report.claimed_signing_time)))
    rows += [
        (messages.REPORT_TIMESTAMP, _timestamp_text(w, report.timestamp)),
        (messages.REPORT_CHANGES, w.t(messages.MODIFICATIONS[report.modifications])),
        (
            messages.REPORT_SIGNED_REVISION,
            w.t(messages.REPORT_SIGNED_BYTES).format(length=report.signed_revision_length),
        ),
    ]
    heading = w.t(messages.REPORT_SIGNATURE).format(
        number=number, total=total, field=report.field_name
    )
    return [
        w.p(heading, w.heading),
        w.result(report.indication),
        w.p(explain_signature(report, catalogue) or ""),
        Spacer(1, 2 * mm),
        w.table(rows),
        Spacer(1, 6 * mm),
    ]


def pdf_report(
    verification: PdfVerification,
    *,
    file_name: str,
    file_sha256: str,
    store: TrustStore,
    language: Language = Language.ES_PE,
) -> bytes:
    """The report of :func:`berigna.core.validation.verify_pdf` as a PDF document."""
    catalogue = translations(language)
    regular, bold = _fonts()
    w = _Writer(catalogue, regular, bold)
    user_roots = sum(1 for entry in store.entries if entry.user_added)
    trust = (
        w.t(messages.REPORT_TRUST_USER) if user_roots else w.t(messages.REPORT_TRUST_OFFICIAL)
    ).format(count=len(store.entries))

    story: list[Any] = [
        w.p(w.t(messages.REPORT_TITLE), w.title),
        Spacer(1, 4 * mm),
        w.table(
            [
                (messages.REPORT_FILE, file_name),
                (messages.REPORT_SHA256, _grouped(file_sha256)),
                (messages.REPORT_VERIFIED_AT, format_time(verification.moment)),
                (messages.REPORT_TRUST, trust),
            ]
        ),
        Spacer(1, 8 * mm),
    ]
    total = len(verification.signatures)
    if total == 0:
        story.append(w.p(w.t(messages.REPORT_NO_SIGNATURES)))
    for number, report in enumerate(verification.signatures, start=1):
        story += _signature_section(w, report, number, total, catalogue)
    if verification.document_timestamps:
        story.append(w.p(w.t(messages.REPORT_DOCUMENT_TIMESTAMPS), w.heading))
        for stamp in verification.document_timestamps:
            story += [
                w.result(stamp.indication),
                w.p(f"{stamp.field_name or ''} · {_timestamp_text(w, stamp)}"),
                w.p(explain_timestamp(stamp, catalogue) or ""),
                Spacer(1, 3 * mm),
            ]
    story.append(Spacer(1, 6 * mm))
    story.append(w.p(w.t(messages.REPORT_GENERATED).format(version=berigna.__version__), w.small))
    if language is not Language.ES_PE:
        story.append(w.p(w.t(messages.REPORT_SPANISH_PREVAILS), w.small))

    def footer(canvas: Any, document: Any) -> None:
        canvas.saveState()
        canvas.setFont(regular, 8)
        canvas.drawRightString(
            A4[0] - 18 * mm, 10 * mm, w.t(messages.REPORT_PAGE).format(page=document.page)
        )
        canvas.restoreState()

    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=w.t(messages.REPORT_TITLE),
        author=f"berigna {berigna.__version__}",
        lang=language.value.replace("_", "-"),
        invariant=True,
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
