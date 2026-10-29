# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Visible signature appearance (RF-012, RF-092; ADR-0018)."""

import datetime as dt
import hashlib
import io
import re
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.reader import PdfFileReader
from reportlab.pdfgen import canvas

from berigna.core.appearance import (
    VERIFY_URL,
    AppearanceKind,
    DniDisplay,
    StampData,
    VisibleSignature,
    qr_payload,
    qr_segments,
    render_appearance,
    signer_name,
    stamp_data,
    stamp_lines,
)
from berigna.core.errors import AppearanceError
from berigna.core.formats.pades import PadesOptions, page_geometry
from berigna.core.i18n import Language
from berigna.core.signing import sign_pdf_file
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import Modifications, verify_pdf
from support.cards import make_card
from support.pki import Pki, build_pki, minimal_pdf

MOMENT = dt.datetime(2026, 10, 28, 20, 53, tzinfo=dt.UTC)
DATA = StampData("QUISPE MAMANI ROSA", "****4321", MOMENT, "Conformidad", "Cusco")


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _certificate(cn: str, serial: str | None) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if serial:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial))
    name = x509.Name(attributes)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(MOMENT - dt.timedelta(days=1))
        .not_valid_after(MOMENT + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_signer_name_drops_the_dnie_suffix() -> None:
    assert signer_name(_certificate("PEREZ LOPEZ JUAN FIR 12345678 hard", None)) == (
        "PEREZ LOPEZ JUAN"
    )
    assert signer_name(_certificate("EMPRESA SAC FAU 20123456789 soft", None)) == "EMPRESA SAC"
    data = stamp_data(_certificate("ROSA FIR 87654321 hard", "PNOPE-87654321"), reason="R")
    assert (data.signer, data.dni, data.reason) == ("ROSA", "****4321", "R")
    certificate = _certificate("ROSA FIR 87654321 hard", "PNOPE-87654321")
    assert stamp_data(certificate, dni=DniDisplay.FULL).dni == "87654321"
    assert stamp_data(certificate, dni=DniDisplay.HIDDEN).dni is None


def test_stamp_lines_in_spanish_and_quechua() -> None:
    lines = [text for _font, text in stamp_lines(DATA, Language.ES_PE)]
    assert lines[:3] == ["Firmado digitalmente por", "QUISPE MAMANI ROSA", "DNI ****4321"]
    assert re.fullmatch(r"Fecha: 2026-10-2\d a las \d\dh\d\d UTC([+-]\d+(:\d\d)?)?", lines[3])
    assert lines[4:] == ["Motivo: Conformidad", "Lugar: Cusco"]
    # Pending Quechua strings fall back to Spanish (RF-092, ADR-0015), never to English.
    assert stamp_lines(DATA, Language.QUZ_PE)[0][1] == "Firmado digitalmente por"
    bare = StampData("ROSA", None, MOMENT)
    assert len(stamp_lines(bare, Language.ES_PE)) == 3


def test_qr_carries_the_signature_and_how_to_verify_it() -> None:
    payload = qr_payload(DATA, Language.ES_PE).splitlines()
    assert payload[0] == "Firmado digitalmente por QUISPE MAMANI ROSA"
    assert payload[1] == "DNI ****4321"
    assert payload[-1] == f"Cómo verificar: {VERIFY_URL}"
    assert "Conformidad" not in "\n".join(payload)  # nothing about the document
    assert "DNI" not in qr_payload(StampData("ROSA", None, MOMENT), Language.ES_PE)


def test_qr_declares_utf8() -> None:
    """ECI 26 before the bytes: without it, a phone read "Cómo" as "C髇o"."""
    from reportlab.graphics.barcode import qrencoder

    code = qrencoder.QRCode(None, qrencoder.QRErrorCorrectLevel.M)
    for segment in qr_segments("Cómo verificar"):
        code.addData(segment)
    code.make()
    # 0111 (ECI) 00011010 (26, UTF-8) 0100 (bytes): 0x71 0xA4.
    assert code.dataCache[:2] == [0x71, 0xA4]


@pytest.mark.parametrize("kind", list(AppearanceKind))
@pytest.mark.parametrize("box", [(0, 0, 220, 70), (0, 0, 110, 150)], ids=["horizontal", "vertical"])
def test_every_kind_embeds_the_brand_typefaces(
    kind: AppearanceKind, box: tuple[float, float, float, float], tmp_path: Path
) -> None:
    """Wider than tall, the graphic goes on the left; taller than wide, above the text."""
    image = None
    if kind in (AppearanceKind.RUBRIC, AppearanceKind.LOGO):
        image = tmp_path / "imagen.png"
        _png(image)
    pdf = render_appearance(VisibleSignature(0, box, kind, image), DATA)
    assert pdf.startswith(b"%PDF")
    assert b"SourceSans3-Regular" in pdf
    assert b"Arvo-Bold" in pdf


def test_long_names_shrink_to_fit() -> None:
    long = StampData("NOMBRE " * 12, "****1", MOMENT, "Motivo " * 10, "Lugar")
    pdf = render_appearance(VisibleSignature(0, (0, 0, 120, 40)), long)
    assert pdf.startswith(b"%PDF")


@pytest.mark.parametrize(
    ("visible", "message"),
    [
        (VisibleSignature(0, (0, 0, 10, 40)), "too small"),
        (VisibleSignature(0, (0, 0, 200, 60), AppearanceKind.LOGO), "no image"),
        (
            VisibleSignature(0, (0, 0, 200, 60), AppearanceKind.RUBRIC, Path("no-existe.png")),
            "cannot read",
        ),
    ],
)
def test_appearance_errors(visible: VisibleSignature, message: str) -> None:
    with pytest.raises(AppearanceError, match=message):
        render_appearance(visible, DATA)


def _png(path: Path) -> None:
    from PIL import Image

    Image.new("RGBA", (60, 30), (107, 34, 50, 255)).save(path)


def _pdf(*, crop: tuple[float, float, float, float] | None = None, rotate: int = 0) -> bytes:
    out = io.BytesIO()
    pdf = canvas.Canvas(out, pagesize=(595, 842), invariant=True)
    if crop is not None:
        pdf.setCropBox(crop)
    if rotate:
        pdf.setPageRotation(rotate)
    pdf.drawString(72, 720, "Documento")
    pdf.showPage()
    pdf.save()
    return out.getvalue()


def test_page_geometry() -> None:
    plain = page_geometry(_pdf(), 0)
    assert (plain.x, plain.y, plain.width, plain.height, plain.rotation) == (0, 0, 595, 842, 0)
    cropped = page_geometry(_pdf(crop=(50, 100, 545, 742)), 0)
    assert (cropped.x, cropped.y, cropped.width, cropped.height) == (50, 100, 495, 642)
    assert page_geometry(_pdf(rotate=90), 0).rotation == 90


def _sign(
    pki: Pki, tmp_path: Path, data: bytes, visible: VisibleSignature
) -> tuple[Path, list[object]]:
    source = tmp_path / "contrato.pdf"
    source.write_bytes(data)
    output = tmp_path / "contrato-firmado.pdf"
    asked: list[object] = []
    card, _leaf = make_card(pki, "QUISPE MAMANI ROSA FIR 87654321 hard")

    def ask_pin(check: object) -> Pin:
        asked.append(check)
        return Pin("123456")

    with DnieV2Token(card) as token:
        sign_pdf_file(
            source,
            output,
            expected_sha256=hashlib.sha256(data).hexdigest(),
            token=token,
            store=pki.store,
            ask_pin=ask_pin,
            options=PadesOptions(reason="Conformidad"),
            online=False,
            visible=visible,
        )
    return output, asked


def test_visible_signature_is_placed_in_page_coordinates(pki: Pki, tmp_path: Path) -> None:
    data = _pdf(crop=(50, 100, 545, 742))
    output, _asked = _sign(pki, tmp_path, data, VisibleSignature(0, (300, 20, 180, 60)))
    reader = PdfFileReader(io.BytesIO(output.read_bytes()))
    [signature] = reader.embedded_signatures
    rect = [float(v) for v in signature.sig_field["/Rect"]]
    assert rect == [350, 120, 530, 180]  # moved by the origin of the crop box
    [report] = verify_pdf(output.read_bytes(), pki.store, online=False).signatures
    assert report.modifications is Modifications.NONE
    assert report.covers_whole_document


@pytest.mark.parametrize(
    ("data", "visible", "message"),
    [
        (minimal_pdf(), VisibleSignature(3, (10, 10, 200, 60)), "does not exist"),
        (_pdf(rotate=90), VisibleSignature(0, (10, 10, 200, 60)), "rotated"),
    ],
)
def test_visible_signature_problems_are_found_before_the_pin(
    pki: Pki, tmp_path: Path, data: bytes, visible: VisibleSignature, message: str
) -> None:
    with pytest.raises(AppearanceError, match=message):
        _sign(pki, tmp_path, data, visible)
    assert not (tmp_path / "contrato-firmado.pdf").exists()


def test_preloaded_images_are_normalised(tmp_path: Path) -> None:
    from PIL import Image

    from berigna.core.appearance import remove_image, store_image, stored_image

    folder = tmp_path / "apariencia"
    assert stored_image(folder, AppearanceKind.RUBRIC) is None
    assert stored_image(folder, AppearanceKind.TEXT) is None
    source = tmp_path / "rubrica.jpg"
    photo = Image.new("RGB", (3000, 1000), (20, 20, 20))
    exif = Image.Exif()
    exif[0x010F] = "Camara de prueba"  # Make
    photo.save(source, format="JPEG", exif=exif)
    kept = store_image(folder, AppearanceKind.RUBRIC, source)
    assert kept == stored_image(folder, AppearanceKind.RUBRIC)
    with Image.open(kept) as image:
        assert image.format == "PNG"
        assert max(image.size) == 1200
        assert not image.getexif()
    remove_image(folder, AppearanceKind.RUBRIC)
    remove_image(folder, AppearanceKind.RUBRIC)  # nothing left: no error
    assert stored_image(folder, AppearanceKind.RUBRIC) is None


def test_unusable_images_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from berigna.core import appearance
    from berigna.core.appearance import store_image

    text = tmp_path / "no-es-imagen.png"
    text.write_text("hola")
    with pytest.raises(AppearanceError, match="cannot read"):
        store_image(tmp_path, AppearanceKind.LOGO, text)
    monkeypatch.setattr(appearance, "MAX_IMAGE_BYTES", 2)
    with pytest.raises(AppearanceError, match="larger than"):
        store_image(tmp_path, AppearanceKind.LOGO, text)
