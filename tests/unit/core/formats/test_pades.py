# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""PAdES B-B through the DNIe v2 driver (simulator): PR-PAD-01, PR-PAD-09, RF-013, RF-014."""

import io

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.general import SigningError
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from berigna.core.errors import PdfFormatError
from berigna.core.formats.pades import PadesOptions, sign_pdf_basic
from berigna.core.token.dnie_v2 import INS_PSO, DnieV2Token
from berigna.core.token.pin import Pin
from sim.dnie_v2 import DnieV2Simulator
from support.cards import make_card
from support.pdfs import pdf_with_freed_info
from support.pki import Pki, build_pki, minimal_pdf


def _asn1(certificate: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _validation_context(pki: Pki) -> ValidationContext:
    return ValidationContext(trust_roots=[_asn1(pki.root)], other_certs=[_asn1(pki.ca)])


def _sign(
    pki: Pki, pdf: bytes, cn: str, options: PadesOptions | None = None
) -> tuple[bytes, DnieV2Simulator]:
    card, leaf = make_card(pki, cn)
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        signed = sign_pdf_basic(pdf, token, [pki.root, pki.ca, leaf], options)
    return signed, card


def test_pades_b_b_is_valid_and_signed_in_the_token(pki: Pki) -> None:
    options = PadesOptions(reason="Prueba", location="Lima, Perú", contact="soporte")
    signed, card = _sign(pki, minimal_pdf(), "FIRMANTE PDF", options)
    signatures = PdfFileReader(io.BytesIO(signed)).embedded_signatures
    assert len(signatures) == 1
    signature = signatures[0]
    assert signature.sig_object["/SubFilter"] == "/ETSI.CAdES.detached"
    assert signature.sig_object["/Reason"] == "Prueba"
    assert signature.sig_object["/Location"] == "Lima, Perú"
    status = validate_pdf_signature(signature, _validation_context(pki))
    assert status.intact
    assert status.valid
    assert status.trusted
    assert card.instructions().count(INS_PSO) == 1  # exactly one operation in the chip


def test_second_signature_keeps_the_first_valid(pki: Pki) -> None:
    """RF-014: incremental update; both signatures stay intact and valid."""
    first, _ = _sign(pki, minimal_pdf(), "PRIMER FIRMANTE")
    second, _ = _sign(pki, first, "SEGUNDO FIRMANTE")
    assert second.startswith(first)
    signatures = PdfFileReader(io.BytesIO(second)).embedded_signatures
    assert len(signatures) == 2
    for signature in signatures:
        status = validate_pdf_signature(signature, _validation_context(pki))
        assert status.intact
        assert status.valid


def test_damaged_pdf_is_rejected_before_using_the_token(pki: Pki) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        with pytest.raises(PdfFormatError):
            sign_pdf_basic(b"%PDF-1.7\nesto no es un PDF", token, [pki.root, pki.ca, leaf])
    assert INS_PSO not in card.instructions()


@pytest.mark.parametrize("digest", ["sha384", "sha512"])
def test_other_digest_algorithms(pki: Pki, digest: str) -> None:
    signed, _ = _sign(pki, minimal_pdf(), "FIRMANTE SHA2", PadesOptions(digest=digest))  # type: ignore[arg-type]
    signature = PdfFileReader(io.BytesIO(signed)).embedded_signatures[0]
    status = validate_pdf_signature(signature, _validation_context(pki))
    assert status.intact
    assert status.valid
    assert status.md_algorithm == digest


def test_unreadable_bytes_are_rejected(pki: Pki) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token, pytest.raises(PdfFormatError, match="cannot read"):
        sign_pdf_basic(b"no es un pdf", token, [pki.root, pki.ca, leaf])
    assert card.headers == []


def test_signer_refuses_a_digest_other_than_the_agreed_one(pki: Pki) -> None:
    import asyncio

    from berigna.core.formats.pades import _TokenPdfSigner

    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token:
        signer = _TokenPdfSigner(token, [pki.root, pki.ca, leaf], "sha256")
        with pytest.raises(ValueError, match="unexpected digest"):
            asyncio.run(signer.async_sign_raw(b"datos", "sha512"))
    assert INS_PSO not in card.instructions()


@pytest.mark.parametrize(
    "error",
    [
        SigningError("document certified with no changes allowed"),
        TypeError("'NullObject' object does not support item assignment"),
    ],
)
def test_pyhanko_signing_errors_are_translated(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """Also pyHanko's own errors on malformed PDFs: ERR-304, not an unexpected error."""

    def failing_sign_pdf(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr("berigna.core.formats.pades.signers.PdfSigner.sign_pdf", failing_sign_pdf)
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token, pytest.raises(PdfFormatError, match="cannot sign"):
        sign_pdf_basic(minimal_pdf(), token, [pki.root, pki.ca, leaf])


def test_pdf_whose_metadata_was_freed_can_be_signed(pki: Pki) -> None:
    """ExifTool deletes /Info by freeing its object and leaves the reference: pyHanko failed
    writing the modification date ('NullObject' object does not support item assignment),
    after the PIN (real document, 2026-10-28). The signature revision gets a new /Info."""
    signed, _card = _sign(pki, pdf_with_freed_info(), "FIRMANTE SIN INFO")
    reader = PdfFileReader(io.BytesIO(signed))
    status = validate_pdf_signature(reader.embedded_signatures[0], _validation_context(pki))
    assert status.bottom_line
    assert "/ModDate" in reader.trailer["/Info"]
