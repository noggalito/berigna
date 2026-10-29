# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signed PDFs for the tests: berigna's own PAdES B-B made with the simulated DNIe."""

import io

from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from cryptography import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.dss import DocumentSecurityStore

from berigna.core.formats.pades import sign_pdf_basic
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from support.cards import make_card
from support.pki import Pki, minimal_pdf


def sign(pki: Pki, pdf: bytes, cn: str = "FIRMANTE") -> tuple[bytes, x509.Certificate]:
    card, leaf = make_card(pki, cn)
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        return sign_pdf_basic(pdf, token, (pki.root, pki.ca, leaf)), leaf


def with_dss(pdf: bytes, ocsps: list[bytes], crls: list[bytes]) -> bytes:
    """Append a DSS (incremental update), as a B-LT signature would carry."""
    contents = next(iter(PdfFileReader(io.BytesIO(pdf)).embedded_signatures)).pkcs7_content
    out = io.BytesIO(pdf)
    DocumentSecurityStore.add_dss(
        out,
        contents,
        ocsps=[asn1_ocsp.OCSPResponse.load(o) for o in ocsps],
        crls=[asn1_crl.CertificateList.load(c) for c in crls],
    )
    return out.getvalue()


def signed_with_revinfo(pki: Pki, *, revoked: bool = False) -> bytes:
    """A signature that verifies offline: TOTAL-PASSED, or REVOKED with ``revoked``."""
    signed, leaf = sign(pki, minimal_pdf())
    return with_dss(signed, [pki.ocsp(leaf, revoked=revoked)], [pki.arl()])
