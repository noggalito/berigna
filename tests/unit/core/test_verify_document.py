# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verifying any signed file by its content (CU-06; RF-050 to RF-052), and the file a
detached signature signs (RF-051)."""

from pathlib import Path

import pytest

from berigna.core.documents import DocumentKind
from berigna.core.errors import UnreadableDocumentError
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.xades import XadesPackaging
from berigna.core.validation import (
    CadesVerification,
    Indication,
    PdfVerification,
    XadesVerification,
)
from berigna.core.verification import is_detached, original_of, verify_document
from support.pki import Pki, build_pki, minimal_pdf
from support.signatures import cades, xades
from support.signed import sign

CONTENT = b"nombre;monto\nRosa;100\n"
XML = b"<acta><punto>1</punto></acta>"


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def test_detached_signatures_are_recognised(pki: Pki) -> None:
    assert is_detached(cades(pki, CONTENT)[0])
    assert not is_detached(cades(pki, CONTENT, CadesPackaging.ENVELOPING)[0])
    assert is_detached(xades(pki, XML, XadesPackaging.DETACHED)[0])
    assert not is_detached(xades(pki, XML, XadesPackaging.ENVELOPED)[0])
    assert not is_detached(xades(pki, XML, XadesPackaging.ENVELOPING)[0])
    assert not is_detached(minimal_pdf())
    assert not is_detached(b"<a><ds:Reference/></a>")
    assert not is_detached(b"<a/>", DocumentKind.XML)


def test_the_original_is_next_to_the_signature(tmp_path: Path) -> None:
    (tmp_path / "acta.xml").write_bytes(XML)
    assert original_of(tmp_path / "acta.xml.p7s") == tmp_path / "acta.xml"
    assert original_of(tmp_path / "acta.xml.XSIG") == tmp_path / "acta.xml"
    assert original_of(tmp_path / "acta-2.xml.p7s") == tmp_path / "acta.xml"  # numbered
    assert original_of(tmp_path / "otra.xml.p7s") is None  # no such file
    assert original_of(tmp_path / "acta.xml.p7m") is None  # a .p7m carries its content
    (tmp_path / "carpeta").mkdir()
    assert original_of(tmp_path / "carpeta.p7s") is None  # a folder is not a file


def test_the_signed_digest_chooses_among_the_candidates(pki: Pki, tmp_path: Path) -> None:
    """Review of the increment 6: "acta-2.xml.p7s" may sign "acta.xml" while an unrelated
    "acta-2.xml" exists; the digest in the signature says which one it is."""
    (tmp_path / "acta.xml").write_bytes(XML)
    (tmp_path / "acta-2.xml").write_bytes(b"<otra/>")
    signature, _leaf = cades(pki, XML)
    path = tmp_path / "acta-2.xml.p7s"
    assert original_of(path) == tmp_path / "acta-2.xml"  # by the name alone
    assert original_of(path, signature) == tmp_path / "acta.xml"
    (tmp_path / "acta.xml").unlink()
    assert original_of(path, signature) == tmp_path / "acta-2.xml"  # the user will see
    (tmp_path / "acta-2.xml").chmod(0)  # unreadable: still the only candidate
    assert original_of(path, signature) == tmp_path / "acta-2.xml"


def test_a_detached_xades_names_its_document(pki: Pki, tmp_path: Path) -> None:
    signature, _leaf = xades(pki, XML, XadesPackaging.DETACHED, reference_uri="acta%20final.xml")
    (tmp_path / "acta final.xml").write_bytes(XML)
    assert original_of(tmp_path / "firma.xsig", signature) == tmp_path / "acta final.xml"
    escaping, _leaf = xades(pki, XML, XadesPackaging.DETACHED, reference_uri="../../etc/passwd")
    assert original_of(tmp_path / "firma.xsig", escaping) is None  # never another folder


def test_each_format_goes_to_its_verifier(pki: Pki) -> None:
    signed_pdf, _leaf = sign(pki, minimal_pdf())
    pdf = verify_document(signed_pdf, pki.store, online=False)
    assert isinstance(pdf, PdfVerification)
    assert len(pdf.signatures) == 1

    signature, _leaf = cades(pki, CONTENT)
    detached = verify_document(signature, pki.store, content=CONTENT, online=False)
    assert isinstance(detached, CadesVerification)
    assert detached.signatures[0].subindication != "HASH_FAILURE"
    wrong = verify_document(signature, pki.store, content=b"otro", online=False)
    assert isinstance(wrong, CadesVerification)
    assert wrong.signatures[0].indication is Indication.TOTAL_FAILED

    document, _leaf = xades(pki, XML)
    xml = verify_document(document, pki.store, online=False)
    assert isinstance(xml, XadesVerification)
    assert len(xml.signatures) == 1


def test_other_files_cannot_be_verified(pki: Pki) -> None:
    with pytest.raises(UnreadableDocumentError):
        verify_document(b"texto sin firma", pki.store, online=False)
