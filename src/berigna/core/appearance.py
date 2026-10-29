# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Appearance of a visible signature (RF-012, RF-092; ADR-0018).

The appearance is drawn here, with ReportLab, as a one-page PDF the size of the signature box,
and pyHanko places it as the static appearance of the signature field. Drawing it here lets
the brand typefaces (Arvo and Source Sans 3, TrueType, in ``fonts/``) be embedded: pyHanko's
own text engine needs uharfbuzz, which Debian does not package.

Four kinds, chosen by the user: text only, a preloaded handwritten signature (rubric), a
preloaded logo, or a QR code. The QR code carries the data of the signature as text and the
address of a page that explains how to verify it; it identifies neither the document nor
anything outside the signature.
"""

import datetime as dt
import enum
import io
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from reportlab.graphics import renderPDF
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.barcode.qrencoder import QRECI, QR8bitByte
from reportlab.graphics.shapes import Drawing
from reportlab.lib.colors import HexColor
from reportlab.lib.utils import ImageReader, simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from berigna.core.errors import AppearanceError
from berigna.core.files import write_atomically
from berigna.core.i18n import Language, translations
from berigna.core.report.explanations import format_time, identity_number, masked_id

FONTS = Path(__file__).parent / "fonts"
VERIFY_URL = "https://berigna.noggalito.com/verificar"
INK = HexColor("#231C1E")  # carbón: neutral, prints well (BRG-UX-002 §6)
ACCENT = HexColor("#6B2232")  # burdeos, only for the thin rule

_TYPEFACES = {
    "berigna-text": "SourceSans3-Regular.ttf",
    "berigna-text-semibold": "SourceSans3-Semibold.ttf",
    "berigna-name": "Arvo-Bold.ttf",
}
_SUFFIX = re.compile(r"\s+(FIR|FAU)\s+\d+(\s+\w+)?\s*$")  # "… FIR 12345678 hard" in a DNIe CN


def N_(message: str) -> str:
    return message


SIGNED_BY = N_("Digitally signed by")
DNI = N_("DNI {dni}")
DATE = N_("Date: {date}")
REASON = N_("Reason: {reason}")
LOCATION = N_("Location: {location}")
HOW_TO_VERIFY = N_("How to verify: {url}")


class DniDisplay(enum.Enum):
    """How the stamp and the QR code show the DNI (decision of 2026-10-28). The certificate
    in the PDF carries it in full anyway: this only concerns what is printed."""

    LAST_FOUR = "last-four"  # ****5678, as in the reports
    FULL = "full"
    HIDDEN = "hidden"


class AppearanceKind(enum.Enum):
    TEXT = "text"
    RUBRIC = "rubric"
    LOGO = "logo"
    QR = "qr"


@dataclass(frozen=True)
class VisibleSignature:
    """Where and how the signature is shown: ``box`` is (x, y, width, height) in PDF points on
    page ``page`` (from 0), with the origin at the bottom left of what a preview shows (the
    crop box). Rotated pages are not supported yet."""

    page: int
    box: tuple[float, float, float, float]
    kind: AppearanceKind = AppearanceKind.TEXT
    image: Path | None = None  # rubric or logo
    language: Language = Language.ES_PE  # fixed texts and date (RF-092)
    dni: DniDisplay = DniDisplay.LAST_FOUR


@dataclass(frozen=True)
class StampData:
    signer: str
    dni: str | None  # as shown: ****1234, 12341234 or None
    moment: dt.datetime
    reason: str | None = None
    location: str | None = None


def signer_name(certificate: x509.Certificate) -> str:
    """The holder's name, without the "FIR 12345678 hard" that DNIe certificates append."""
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common = str(names[0].value) if names else certificate.subject.rfc4514_string()
    return _SUFFIX.sub("", common).strip()


def stamp_data(
    certificate: x509.Certificate,
    *,
    dni: DniDisplay = DniDisplay.LAST_FOUR,
    moment: dt.datetime | None = None,
    reason: str | None = None,
    location: str | None = None,
) -> StampData:
    shown = None
    if dni is DniDisplay.LAST_FOUR:
        shown = masked_id(certificate)
    elif dni is DniDisplay.FULL:
        shown = identity_number(certificate)
    return StampData(
        signer=signer_name(certificate),
        dni=shown,
        moment=moment or dt.datetime.now().astimezone(),
        reason=reason,
        location=location,
    )


def stamp_lines(data: StampData, language: Language) -> list[tuple[str, str]]:
    """(typeface, text) of every line of the stamp, in ``language``."""
    t = translations(language).gettext
    lines = [("berigna-text", t(SIGNED_BY)), ("berigna-name", data.signer)]
    if data.dni:
        lines.append(("berigna-text-semibold", t(DNI).format(dni=data.dni)))
    lines.append(("berigna-text", t(DATE).format(date=format_time(data.moment, t))))
    if data.reason:
        lines.append(("berigna-text", t(REASON).format(reason=data.reason)))
    if data.location:
        lines.append(("berigna-text", t(LOCATION).format(location=data.location)))
    return lines


def qr_payload(data: StampData, language: Language) -> str:
    """Text of the QR code: the data of the signature and how to verify it (decision of
    2026-10-28: both). It never names the document."""
    t = translations(language).gettext
    lines = [f"{t(SIGNED_BY)} {data.signer}"]
    if data.dni:
        lines.append(t(DNI).format(dni=data.dni))
    lines.append(t(DATE).format(date=format_time(data.moment, t)))
    # No signature level: the stamp is drawn before signing, and B-LT may end as B-T.
    lines.append(t(HOW_TO_VERIFY).format(url=VERIFY_URL))
    return "\n".join(lines)


UTF8_ECI = 26


def qr_segments(text: str) -> list[QRECI | QR8bitByte]:
    """``text`` as UTF-8 bytes preceded by the ECI that says so. Without it, readers guess the
    encoding, and some phones read "Cómo" as "C髇o" (test of 2026-10-28)."""
    return [QRECI(UTF8_ECI), QR8bitByte(text.encode("utf-8"))]


def _register_fonts() -> None:
    for name, file in _TYPEFACES.items():
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(FONTS / file)))


def _fit(
    lines: list[tuple[str, str]], width: float, height: float
) -> tuple[float, list[tuple[str, float, str]]]:
    """The largest size (up to 10 pt) at which the wrapped lines fit in width by height."""
    size = 10.0
    while True:
        wrapped = []
        for font, text in lines:
            scale = 1.15 if font == "berigna-name" else 1.0
            for part in simpleSplit(text, font, size * scale, width) or [""]:
                wrapped.append((font, size * scale, part))
        total = sum(points * 1.2 for _font, points, _part in wrapped)
        if total <= height or size <= 4:
            return size, wrapped
        size -= 0.25


def render_appearance(visible: VisibleSignature, data: StampData) -> bytes:
    """The appearance as a one-page PDF the size of ``visible.box``; transparent background."""
    _register_fonts()
    _x, _y, width, height = visible.box
    if width < 20 or height < 10:
        raise AppearanceError(f"signature box too small: {width:.0f} x {height:.0f} pt")
    out = io.BytesIO()
    pdf = canvas.Canvas(out, pagesize=(width, height), invariant=True)
    pad = max(2.0, min(width, height) * 0.06)
    left = pad

    if visible.kind is not AppearanceKind.TEXT:
        side = height - 2 * pad
        if visible.kind is AppearanceKind.QR:
            widget = QrCodeWidget(qr_segments(qr_payload(data, visible.language)), barLevel="M")
            x1, y1, x2, y2 = widget.getBounds()
            drawing = Drawing(side, side)
            widget.barFillColor = INK
            drawing.add(widget)
            drawing.scale(side / (x2 - x1), side / (y2 - y1))
            renderPDF.draw(drawing, pdf, pad, pad)
            left += side + pad
        else:
            if visible.image is None:
                raise AppearanceError(f"no image for a {visible.kind.value} appearance")
            try:
                image = ImageReader(str(visible.image))
                image_width, image_height = image.getSize()
            except (OSError, ValueError) as exc:
                raise AppearanceError(f"cannot read {visible.image.name}: {exc}") from exc
            ratio = image_width / image_height
            box_width = min(width * 0.4, side * ratio)
            box_height = box_width / ratio
            pdf.drawImage(image, pad, (height - box_height) / 2, box_width, box_height, mask="auto")
            left += box_width + pad

    pdf.setStrokeColor(ACCENT)
    pdf.setLineWidth(0.8)
    pdf.line(left, pad, left, height - pad)
    text_left = left + pad
    _size, wrapped = _fit(
        stamp_lines(data, visible.language), width - text_left - pad, height - 2 * pad
    )
    total = sum(points * 1.2 for _font, points, _part in wrapped)
    y = height - (height - total) / 2
    pdf.setFillColor(INK)
    for font, points, part in wrapped:
        y -= points * 1.2
        pdf.setFont(font, points)
        pdf.drawString(text_left, y + points * 0.25, part)
    pdf.showPage()
    pdf.save()
    return out.getvalue()


# -- Preloaded images (rubric and logo) ----------------------------------------------------------

IMAGE_FILES = {AppearanceKind.RUBRIC: "rubrica.png", AppearanceKind.LOGO: "logotipo.png"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_SIDE = 1200  # pixels; enough for a box printed at 300 dpi


def stored_image(directory: Path, kind: AppearanceKind) -> Path | None:
    """The preloaded image of ``kind`` (rubric or logo), if there is one."""
    name = IMAGE_FILES.get(kind)
    if name is None:
        return None
    path = directory / name
    return path if path.is_file() else None


def store_image(directory: Path, kind: AppearanceKind, source: Path) -> Path:
    """Keep ``source`` as the image of ``kind``: re-encoded as PNG, which drops its metadata
    (EXIF may carry a location or a camera), and reduced to :data:`MAX_IMAGE_SIDE`."""
    from PIL import Image, UnidentifiedImageError

    name = IMAGE_FILES[kind]
    try:
        if source.stat().st_size > MAX_IMAGE_BYTES:
            raise AppearanceError(f"{source.name} is larger than {MAX_IMAGE_BYTES} bytes")
        with Image.open(source) as image:
            image.load()
            picture = image.convert("RGBA")
    except (OSError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
        raise AppearanceError(f"cannot read {source.name}: {exc}") from exc
    picture.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
    out = io.BytesIO()
    picture.save(out, format="PNG")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    write_atomically(target, out.getvalue(), replace=True)
    return target


def remove_image(directory: Path, kind: AppearanceKind) -> None:
    path = stored_image(directory, kind)
    if path is not None:
        path.unlink()
