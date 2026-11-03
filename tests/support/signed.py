# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signed PDFs for the tests: berigna's own PAdES B-B made with the simulated DNIe, and B-T
to B-LTA made with pyHanko and a test TSA."""

import io

from asn1crypto import crl as asn1_crl
from asn1crypto import keys as asn1_keys
from asn1crypto import ocsp as asn1_ocsp
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from berigna.core.certs import to_asn1
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


def asn1_key(key: rsa.RSAPrivateKey) -> asn1_keys.PrivateKeyInfo:
    return asn1_keys.PrivateKeyInfo.load(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def pades(
    pki: Pki,
    level: str,
    *,
    leaf_days: tuple[int, int] = (-1, 365),
    tsa_pki: Pki | None = None,
) -> tuple[bytes, x509.Certificate]:
    """B-T, B-LT or B-LTA made with pyHanko and a test TSA, with the revocation data of the
    signer and of the TSA embedded from B-LT on (the verifier tests and R-DES-10)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf("FIRMANTE " + level, key=key, days=leaf_days)
    issuer = tsa_pki or pki
    tsa_cert, tsa_key = issuer.tsa()
    registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    registry.register(to_asn1(pki.ca))
    tsa_registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    tsa_registry.register(to_asn1(issuer.ca))
    signer = signers.SimpleSigner(
        signing_cert=to_asn1(leaf), signing_key=asn1_key(key), cert_registry=registry
    )
    timestamper = DummyTimeStamper(
        tsa_cert=to_asn1(tsa_cert), tsa_key=asn1_key(tsa_key), certs_to_embed=tsa_registry
    )
    embed = level in ("B-LT", "B-LTA")
    context = ValidationContext(
        trust_roots=[to_asn1(pki.root), to_asn1(issuer.root)],
        other_certs=[to_asn1(pki.ca), to_asn1(issuer.ca)],
        ocsps=[
            asn1_ocsp.OCSPResponse.load(pki.ocsp(leaf)),
            asn1_ocsp.OCSPResponse.load(issuer.ocsp(tsa_cert)),
        ],
        crls=[asn1_crl.CertificateList.load(c) for c in {pki.arl(), issuer.arl()}],
        allow_fetching=False,
    )
    metadata = signers.PdfSignatureMetadata(
        field_name="Firma",
        subfilter=SigSeedSubFilter.PADES,
        embed_validation_info=embed,
        use_pades_lta=level == "B-LTA",
        validation_context=context if embed else None,
    )
    writer = IncrementalPdfFileWriter(io.BytesIO(minimal_pdf()))
    signed = signers.sign_pdf(writer, metadata, signer=signer, timestamper=timestamper)
    return signed.getvalue(), tsa_cert
