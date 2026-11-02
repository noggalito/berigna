# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
import hashlib
from pathlib import Path

import pytest
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.sign.fields import MDPPerm

from berigna.core.documents import (
    DocumentKind,
    TextPreview,
    detect_kind,
    inspect_document,
    text_preview,
)
from berigna.core.errors import UnreadableDocumentError
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.pades import sign_pdf_basic
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from support.cards import make_card
from support.certified import certified_pdf
from support.pki import Pki, build_pki, minimal_pdf
from support.signatures import cades, xades


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def test_unsigned_pdf(tmp_path: Path) -> None:
    data = minimal_pdf()
    path = tmp_path / "contrato.pdf"
    path.write_bytes(data)
    info = inspect_document(path)
    assert info.kind is DocumentKind.PDF
    assert (info.pages, info.signatures, info.signed) == (1, 0, False)
    assert info.size == len(data)
    assert info.sha256 == hashlib.sha256(data).hexdigest()


def test_signed_pdf(tmp_path: Path, pki: Pki) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        signed = sign_pdf_basic(minimal_pdf(), token, (pki.root, pki.ca, leaf))
    path = tmp_path / "firmado.pdf"
    path.write_bytes(signed)
    info = inspect_document(path)
    assert (info.kind, info.signatures, info.signed) == (DocumentKind.PDF, 1, True)


@pytest.mark.parametrize(
    ("permission", "locked"), [(MDPPerm.NO_CHANGES, True), (MDPPerm.FILL_FORMS, False)]
)
def test_certified_documents(tmp_path: Path, pki: Pki, permission: MDPPerm, locked: bool) -> None:
    path = tmp_path / "certificado.pdf"
    path.write_bytes(certified_pdf(pki, permission))
    assert inspect_document(path).locked is locked


def test_header_after_leading_bytes_is_treated_as_a_pdf(tmp_path: Path) -> None:
    """Readers accept junk before the header; such a file is a damaged PDF, not "other"."""
    path = tmp_path / "con-prefijo.pdf"
    path.write_bytes(b"basura\n" + minimal_pdf())
    with pytest.raises(UnreadableDocumentError):
        inspect_document(path)


def test_header_starting_at_the_end_of_the_first_kilobyte(tmp_path: Path) -> None:
    """The header may start at byte 1023 and end after the kilobyte: still a PDF."""
    path = tmp_path / "cabecera-tardia.pdf"
    path.write_bytes(b" " * 1020 + b"%PDF-1.7\n")
    with pytest.raises(UnreadableDocumentError):
        inspect_document(path)


def test_a_late_pdf_header_is_not_a_pdf(tmp_path: Path) -> None:
    path = tmp_path / "datos.xml"
    path.write_bytes(b"<a>%PDF- only later</a>".rjust(2000))
    info = inspect_document(path)
    assert (info.kind, info.pages, info.signatures) == (DocumentKind.XML, None, 0)


def test_damaged_pdf(tmp_path: Path) -> None:
    path = tmp_path / "roto.pdf"
    path.write_bytes(b"%PDF-1.7\nnot really a pdf")
    with pytest.raises(UnreadableDocumentError):
        inspect_document(path)


def test_unreadable_certification_data_is_left_to_pyhanko(
    tmp_path: Path, pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_reader: object) -> None:
        raise PdfError("bad /Perms")

    monkeypatch.setattr("berigna.core.formats.pades.read_certification_data", broken)
    path = tmp_path / "certificado.pdf"
    path.write_bytes(certified_pdf(pki, MDPPerm.NO_CHANGES))
    assert inspect_document(path).locked is False


# -- Files that are not PDF (CU-05) ----------------------------------------------------------------


def test_xml_documents_and_their_signatures(tmp_path: Path, pki: Pki) -> None:
    path = tmp_path / "acta.xml"
    path.write_bytes(b"\xef\xbb\xbf<acta/>")  # with a BOM
    assert (inspect_document(path).kind, inspect_document(path).signatures) == (
        DocumentKind.XML,
        0,
    )
    signed, _leaf = xades(pki, b"<acta/>")
    path.write_bytes(signed)
    info = inspect_document(path)
    assert (info.kind, info.signatures, info.signed) == (DocumentKind.XML, 1, True)
    assert detect_kind(b"<no es xml") == (DocumentKind.OTHER, 0)


def test_cades_signatures(tmp_path: Path, pki: Pki) -> None:
    signature, _leaf = cades(pki, b"contenido")
    path = tmp_path / "acta.pdf.p7s"
    path.write_bytes(signature)
    info = inspect_document(path)
    assert (info.kind, info.signatures) == (DocumentKind.CADES, 1)
    assert detect_kind(b"\x30\x03\x02\x01\x00") == (DocumentKind.OTHER, 0)  # DER, not a CMS


@pytest.mark.parametrize(
    ("data", "text"),
    [
        ("año 2026\n".encode(), "año 2026\n"),
        (b"\xef\xbb\xbfcon BOM", "con BOM"),
        ("utf-16 ñ".encode("utf-16"), "utf-16 ñ"),
        (
            '<?xml version="1.0" encoding="ISO-8859-1"?><a>ñ</a>'.encode("latin-1"),
            '<?xml version="1.0" encoding="ISO-8859-1"?><a>ñ</a>',
        ),
        (b"", ""),
    ],
)
def test_text_files_are_shown(data: bytes, text: str) -> None:
    assert text_preview(data) == TextPreview(text, truncated=False)


@pytest.mark.parametrize(
    "data",
    [
        b"PK\x03\x04\x00\x00binario",
        b"\xff\xfe\xfd no es utf-8",
        b"<a encoding='x'>\x01</a>",
        '<?xml version="1.0" encoding="NO-EXISTE"?><a>\xf1</a>'.encode("latin-1"),
        # an encoding libxml2 knows and Python does not: not shown as UTF-8 by mistake
        '<?xml version="1.0" encoding="ARMSCII-8"?><a>\xf1</a>'.encode("latin-1"),
    ],
)
def test_binary_files_are_not_shown(data: bytes) -> None:
    assert text_preview(data) is None


def test_a_large_text_is_cut_without_breaking_a_character() -> None:
    data = "ñ".encode() * 10  # two bytes each: a cut at 5 falls inside the third
    preview = text_preview(data, limit=5)
    assert preview == TextPreview("ññ", truncated=True)


def test_a_p7m_of_a_pdf_is_a_cades_signature(tmp_path: Path, pki: Pki) -> None:
    """Review of the increment 6: the PDF inside a .p7m is within its first kilobyte."""
    signature, _leaf = cades(pki, minimal_pdf(), CadesPackaging.ENVELOPING)
    assert b"%PDF-" in signature[:1024]
    path = tmp_path / "contrato.pdf.p7m"
    path.write_bytes(signature)
    assert (inspect_document(path).kind, inspect_document(path).signatures) == (
        DocumentKind.CADES,
        1,
    )


def test_a_damaged_cms_body_is_just_a_file(pki: Pki) -> None:
    """Review of the increment 6: asn1crypto fails late, on reading the damaged body."""
    signature, _leaf = cades(pki, b"contenido")
    damaged = signature[:40]  # a sound header, a body cut short
    assert detect_kind(damaged) == (DocumentKind.OTHER, 0)
