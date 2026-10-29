# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
import hashlib
from pathlib import Path

import pytest
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.sign.fields import MDPPerm

from berigna.core.documents import DocumentKind, inspect_document
from berigna.core.errors import UnreadableDocumentError
from berigna.core.formats.pades import sign_pdf_basic
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from support.cards import make_card
from support.certified import certified_pdf
from support.pki import Pki, build_pki, minimal_pdf


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


def test_other_files_are_not_parsed(tmp_path: Path) -> None:
    path = tmp_path / "datos.xml"
    path.write_bytes(b"<a>%PDF- only later</a>".rjust(2000))
    info = inspect_document(path)
    assert (info.kind, info.pages, info.signatures) == (DocumentKind.OTHER, None, 0)


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
