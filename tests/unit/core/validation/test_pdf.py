# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""PAdES verification (RF-050, RF-053, RF-055): ETSI indications and later modifications."""

import asyncio
import datetime as dt
import io
from typing import Any

import pytest
import requests
from asn1crypto import crl as asn1_crl
from asn1crypto import keys as asn1_keys
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.errors import CRLFetchError
from pyhanko_certvalidator.registry import SimpleCertificateStore

from berigna.core.errors import UnreadableDocumentError
from berigna.core.formats.pades import sign_pdf_basic
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.trust import TrustStore
from berigna.core.validation import Indication, Modifications, verify_pdf
from berigna.core.validation.pdf import _CaOnlyCrlFetcher, _modifications
from support.cards import make_card
from support.pki import NOW, Pki, build_pki, minimal_pdf


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _asn1(cert: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _asn1_key(key: rsa.RSAPrivateKey) -> asn1_keys.PrivateKeyInfo:
    return asn1_keys.PrivateKeyInfo.load(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _sign(pki: Pki, pdf: bytes, cn: str = "FIRMANTE") -> tuple[bytes, x509.Certificate]:
    """PAdES B-B made by berigna itself, with the simulated DNIe."""
    card, leaf = make_card(pki, cn)
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        return sign_pdf_basic(pdf, token, (pki.root, pki.ca, leaf)), leaf


def _with_dss(pdf: bytes, ocsps: list[bytes], crls: list[bytes]) -> bytes:
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


def _signed_with_revinfo(pki: Pki, revoked: bool = False) -> tuple[bytes, x509.Certificate]:
    signed, leaf = _sign(pki, minimal_pdf())
    return _with_dss(signed, [pki.ocsp(leaf, revoked=revoked)], [pki.arl()]), leaf


def _incremental(pdf: bytes, change: Any) -> bytes:
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    change(writer)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_valid_signature_with_embedded_revocation_data(pki: Pki) -> None:
    data, leaf = _signed_with_revinfo(pki)
    result = verify_pdf(data, pki.store, online=False)
    [report] = result.signatures
    assert report.indication is Indication.TOTAL_PASSED
    assert report.subindication is None
    assert report.signer == leaf
    assert report.field_name == "FirmaBerigna1"
    assert report.subfilter == "/ETSI.CAdES.detached"
    assert report.claimed_signing_time is not None
    assert result.document_timestamps == ()
    assert report.timestamp is None


def test_adding_validation_data_does_not_count_as_a_change(pki: Pki) -> None:
    """The DSS is appended after signing: LTA updates only, the content is unchanged."""
    signed, _ = _sign(pki, minimal_pdf())
    data = _with_dss(signed, [], [pki.arl()])
    [report] = verify_pdf(data, pki.store, online=False).signatures
    assert report.modifications is Modifications.LTA_UPDATES
    assert report.document_unchanged_since_signing
    assert not report.covers_whole_document
    assert data[: report.signed_revision_length] == signed  # RF-055: the signed version


def test_without_revocation_data_the_result_is_indeterminate(pki: Pki) -> None:
    signed, _ = _sign(pki, minimal_pdf())
    [report] = verify_pdf(signed, pki.store, online=False).signatures
    assert report.indication is Indication.INDETERMINATE
    assert report.covers_whole_document
    assert report.modifications is Modifications.NONE


def test_revoked_signer_is_reported(pki: Pki) -> None:
    data, _ = _signed_with_revinfo(pki, revoked=True)
    [report] = verify_pdf(data, pki.store, online=False).signatures
    assert report.indication is Indication.INDETERMINATE
    assert report.subindication == "REVOKED_NO_POE"


def test_altered_content_fails_the_hash_check(pki: Pki) -> None:
    signed, _ = _sign(pki, minimal_pdf())
    tampered = bytearray(signed)
    tampered[signed.index(b"Documento de prueba")] = ord("X")
    [report] = verify_pdf(bytes(tampered), pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "HASH_FAILURE"


def test_signer_outside_the_trust_store_is_indeterminate(pki: Pki) -> None:
    data, _ = _signed_with_revinfo(pki)
    other = build_pki()
    [report] = verify_pdf(data, other.store, online=False).signatures
    assert report.indication is Indication.INDETERMINATE
    assert report.subindication == "NO_CERTIFICATE_CHAIN_FOUND"


def test_content_added_after_signing_is_flagged(pki: Pki) -> None:
    """Incremental Saving Attack (AM-05): the signature stays intact, the change is reported."""
    data, _ = _signed_with_revinfo(pki)

    def replace_page_content(writer: IncrementalPdfFileWriter) -> None:
        page = writer.root["/Pages"]["/Kids"][0].get_object()
        stream = generic.StreamObject(stream_data=b"BT /F1 14 Tf 72 700 Td (PAGARE) Tj ET")
        page[generic.NameObject("/Contents")] = writer.add_object(stream)
        writer.update_container(page)

    modified = _incremental(data, replace_page_content)
    [report] = verify_pdf(modified, pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_PASSED  # what was signed is still intact
    assert report.modifications is Modifications.OTHER
    assert not report.document_unchanged_since_signing
    assert data.startswith(modified[: report.signed_revision_length])  # the version signed


def test_successive_signatures_are_reported_in_order(pki: Pki) -> None:
    first, _ = _sign(pki, minimal_pdf(), "PRIMER FIRMANTE")
    both, second_leaf = _sign(pki, first, "SEGUNDO FIRMANTE")
    reports = verify_pdf(both, pki.store, online=False).signatures
    assert [r.field_name for r in reports] == ["FirmaBerigna1", "FirmaBerigna2"]
    assert reports[0].modifications is Modifications.FORM_FILLING  # a new signature field
    assert reports[1].modifications is Modifications.NONE
    assert reports[1].signer == second_leaf


def test_legacy_adobe_signature_with_archived_revocation_data(pki: Pki) -> None:
    """adbe.pkcs7.detached with revocationInfoArchival, as in State documents (SPK-04 §3.6)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf("FIRMANTE ADOBE", key=key)
    registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    registry.register(_asn1(pki.ca))
    signer = signers.SimpleSigner(
        signing_cert=_asn1(leaf), signing_key=_asn1_key(key), cert_registry=registry
    )
    context = ValidationContext(
        trust_roots=[_asn1(pki.root)],
        other_certs=[_asn1(pki.ca)],
        ocsps=[asn1_ocsp.OCSPResponse.load(pki.ocsp(leaf))],
        crls=[asn1_crl.CertificateList.load(pki.arl())],
        allow_fetching=False,
    )
    metadata = signers.PdfSignatureMetadata(
        field_name="Legado",
        subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        embed_validation_info=True,
        validation_context=context,
    )
    out = signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(minimal_pdf())), metadata, signer=signer
    )
    [report] = verify_pdf(out.getvalue(), pki.store, online=False).signatures
    assert report.subfilter == "/adbe.pkcs7.detached"
    assert report.indication is Indication.TOTAL_PASSED


def _pades(
    pki: Pki,
    level: str,
    *,
    leaf_days: tuple[int, int] = (-1, 365),
    tsa_pki: Pki | None = None,
) -> tuple[bytes, x509.Certificate]:
    """B-T, B-LT or B-LTA made with pyHanko and a test TSA (berigna's own TSA client is next)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf("FIRMANTE " + level, key=key, days=leaf_days)
    issuer = tsa_pki or pki
    tsa_cert, tsa_key = issuer.tsa()
    registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    registry.register(_asn1(pki.ca))
    tsa_registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    tsa_registry.register(_asn1(issuer.ca))
    signer = signers.SimpleSigner(
        signing_cert=_asn1(leaf), signing_key=_asn1_key(key), cert_registry=registry
    )
    timestamper = DummyTimeStamper(
        tsa_cert=_asn1(tsa_cert), tsa_key=_asn1_key(tsa_key), certs_to_embed=tsa_registry
    )
    embed = level in ("B-LT", "B-LTA")
    context = ValidationContext(
        trust_roots=[_asn1(pki.root), _asn1(issuer.root)],
        other_certs=[_asn1(pki.ca), _asn1(issuer.ca)],
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


def test_b_lt_signature_reports_its_timestamp(pki: Pki) -> None:
    result = verify_pdf(_pades(pki, "B-LT")[0], pki.store, online=False)
    [report] = result.signatures
    assert report.indication is Indication.TOTAL_PASSED
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.TOTAL_PASSED
    assert report.timestamp.time is not None
    assert report.timestamp.tsa is not None
    assert report.timestamp.tsa.subject.rfc4514_string() == "CN=TEST TSA,C=PE"
    assert result.document_timestamps == ()


def test_b_lta_document_timestamp_is_verified(pki: Pki) -> None:
    result = verify_pdf(_pades(pki, "B-LTA")[0], pki.store, online=False)
    [report] = result.signatures
    [stamp] = result.document_timestamps
    assert report.indication is Indication.TOTAL_PASSED
    assert report.document_unchanged_since_signing
    assert stamp.indication is Indication.TOTAL_PASSED
    assert stamp.field_name is not None
    assert stamp.time is not None


def test_expired_certificate_passes_with_proof_of_existence(pki: Pki) -> None:
    """RF-056: the time-stamps prove the signature existed while the certificate was valid.

    The last document time-stamp is validated at the verification moment, so its TSA needs
    revocation data from then: supplied here, fetched online in real use.
    """
    data, tsa_cert = _pades(pki, "B-LTA", leaf_days=(-10, 1))
    moment = NOW + dt.timedelta(days=3)
    result = verify_pdf(
        data,
        pki.store,
        moment=moment,
        online=False,
        ocsp_responses=[pki.ocsp(tsa_cert, at=moment)],
        crls=[pki.arl()],
    )
    assert result.signatures[0].indication is Indication.TOTAL_PASSED
    assert result.document_timestamps[0].indication is Indication.TOTAL_PASSED


def test_expired_certificate_without_timestamp_is_indeterminate(pki: Pki) -> None:
    data, _ = _signed_with_revinfo(pki)
    moment = NOW + dt.timedelta(days=400)  # the test leaf is valid for 365 days
    [report] = verify_pdf(data, pki.store, moment=moment, online=False).signatures
    assert report.indication is Indication.INDETERMINATE


def test_timestamp_from_an_untrusted_tsa_is_reported(pki: Pki) -> None:
    other = build_pki()
    result = verify_pdf(_pades(pki, "B-LT", tsa_pki=other)[0], pki.store, online=False)
    [report] = result.signatures
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.INDETERMINATE
    assert report.indication is not Indication.TOTAL_PASSED


def test_unprocessable_document_timestamp_is_a_format_failure(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _ = _pades(pki, "B-LTA")

    def broken(self: EmbeddedPdfSignature) -> bytes:
        raise ValueError("bad byte range")

    monkeypatch.setattr(EmbeddedPdfSignature, "compute_digest", broken)
    [stamp] = verify_pdf(data, pki.store, online=False).document_timestamps
    assert stamp.indication is Indication.TOTAL_FAILED
    assert stamp.subindication == "FORMAT_FAILURE"


def test_unsigned_pdf_gives_an_empty_report(pki: Pki) -> None:
    result = verify_pdf(minimal_pdf(), pki.store, online=False)
    assert result.signatures == ()
    assert result.document_timestamps == ()


def test_unreadable_file_is_an_error(pki: Pki) -> None:
    with pytest.raises(UnreadableDocumentError) as info:
        verify_pdf(b"esto no es un PDF", pki.store)
    assert info.value.code == "ERR-401"


def test_partial_coverage_is_a_format_failure(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    """A byte range that does not span a whole revision (signature wrapping, AM-05)."""
    from pyhanko.sign.validation.status import SignatureCoverageLevel

    data, _ = _signed_with_revinfo(pki)
    original = EmbeddedPdfSignature.summarise_integrity_info

    def partial(self: EmbeddedPdfSignature) -> dict[str, Any]:
        info = original(self)
        return {**info, "coverage": SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START}

    monkeypatch.setattr(EmbeddedPdfSignature, "summarise_integrity_info", partial)
    [report] = verify_pdf(data, pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "FORMAT_FAILURE"
    assert report.signer is None


def test_unprocessable_signature_is_a_format_failure(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _ = _signed_with_revinfo(pki)

    def broken(self: EmbeddedPdfSignature) -> bytes:
        raise ValueError("bad byte range")

    monkeypatch.setattr(EmbeddedPdfSignature, "compute_digest", broken)
    [report] = verify_pdf(data, pki.store, online=False).signatures
    assert report.subindication == "FORMAT_FAILURE"


def test_online_verification_with_unreachable_services(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    urls: list[str] = []

    def refuse(url: str, *args: object, **kwargs: object) -> requests.Response:
        urls.append(url)
        raise requests.ConnectionError(f"no route to {url}")

    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    signed, _ = _sign(pki, minimal_pdf())
    [report] = verify_pdf(signed, pki.store, online=True, timeout=1.0).signatures
    assert report.indication is Indication.INDETERMINATE
    assert urls  # the services in the certificates were tried


class FakeCrlFetcher:
    def __init__(self) -> None:
        self.fetched: list[Any] = []

    async def fetch(self, cert: Any, *, use_deltas: Any = None) -> list[Any]:
        self.fetched.append(cert)
        return []

    def fetched_crls(self) -> list[Any]:
        return ["crl"]

    def fetched_crls_for_cert(self, cert: Any) -> list[Any]:
        return ["crl-for-cert"]


def test_end_entity_crls_are_never_downloaded(pki: Pki) -> None:
    """RF-063: the CRL of the DNIe issuing CA weighs ~109 MB."""
    inner = FakeCrlFetcher()
    fetcher = _CaOnlyCrlFetcher(inner)  # type: ignore[arg-type]
    with pytest.raises(CRLFetchError):
        asyncio.run(fetcher.fetch(_asn1(pki.leaf("FIRMANTE"))))
    assert asyncio.run(fetcher.fetch(_asn1(pki.ca))) == []
    assert [c.dump() for c in inner.fetched] == [_asn1(pki.ca).dump()]
    assert list(fetcher.fetched_crls()) == ["crl"]
    assert list(fetcher.fetched_crls_for_cert(_asn1(pki.ca))) == ["crl-for-cert"]


def test_modification_levels_map_to_reported_categories() -> None:
    from pyhanko.sign.diff_analysis import DiffResult, ModificationLevel

    assert _modifications({}) is Modifications.NONE
    assert _modifications({"diff_result": DiffResult(ModificationLevel.ANNOTATIONS, set())}) is (
        Modifications.ANNOTATIONS
    )
    assert _modifications({"diff_result": DiffResult(ModificationLevel.OTHER, set())}) is (
        Modifications.OTHER
    )
    assert _modifications({"docmdp_ok": False}) is Modifications.OTHER


def test_empty_trust_store_trusts_nothing(pki: Pki) -> None:
    data, _ = _signed_with_revinfo(pki)
    [report] = verify_pdf(data, TrustStore([]), online=False).signatures
    assert report.indication is Indication.INDETERMINATE
