# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""PAdES verification (RF-050, RF-053, RF-055): ETSI indications and later modifications."""

import datetime as dt
import io
from dataclasses import dataclass
from typing import Any

import pytest
import requests
from asn1crypto import cms
from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import given, settings
from hypothesis import strategies as st
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import (
    ExpiredError,
    InsufficientRevinfoError,
    NotYetValidError,
    PathValidationError,
)
from pyhanko_certvalidator.registry import SimpleCertificateStore

from berigna.core.certs import to_asn1
from berigna.core.errors import UnreadableDocumentError
from berigna.core.formats.pades import sign_pdf_basic
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.trust import TrustStore
from berigna.core.validation import Indication, Modifications, verify_pdf
from berigna.core.validation.pdf import _modifications
from support.cards import make_card
from support.pki import NOW, Pki, build_pki, minimal_pdf
from support.signed import asn1_key, pades


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


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
    assert report.subindication == "TRY_LATER"  # ETSI §5.2.6, as DSS reports it
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
    registry.register(to_asn1(pki.ca))
    signer = signers.SimpleSigner(
        signing_cert=to_asn1(leaf), signing_key=asn1_key(key), cert_registry=registry
    )
    context = ValidationContext(
        trust_roots=[to_asn1(pki.root)],
        other_certs=[to_asn1(pki.ca)],
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


def test_b_lt_signature_reports_its_timestamp(pki: Pki) -> None:
    result = verify_pdf(pades(pki, "B-LT")[0], pki.store, online=False)
    [report] = result.signatures
    assert report.indication is Indication.TOTAL_PASSED
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.TOTAL_PASSED
    assert report.timestamp.time is not None
    assert report.timestamp.tsa is not None
    assert report.timestamp.tsa.subject.rfc4514_string() == "CN=TEST TSA,C=PE"
    assert result.document_timestamps == ()


def test_b_lta_document_timestamp_is_verified(pki: Pki) -> None:
    result = verify_pdf(pades(pki, "B-LTA")[0], pki.store, online=False)
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
    data, tsa_cert = pades(pki, "B-LTA", leaf_days=(-10, 1))
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
    result = verify_pdf(pades(pki, "B-LT", tsa_pki=other)[0], pki.store, online=False)
    [report] = result.signatures
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.INDETERMINATE
    assert report.indication is not Indication.TOTAL_PASSED


def test_unprocessable_document_timestamp_is_a_format_failure(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _ = pades(pki, "B-LTA")

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


@pytest.mark.parametrize(
    ("error", "subindication"),
    [
        (ExpiredError, "OUT_OF_BOUNDS_NO_POE"),
        (NotYetValidError, "NOT_YET_VALID"),
        (InsufficientRevinfoError, "TRY_LATER"),
        (PathValidationError, "CERTIFICATE_CHAIN_GENERAL_FAILURE"),
        (None, "TRY_LATER"),  # passes on the second look: the first failure was transient
    ],
)
def test_generic_chain_failure_is_diagnosed(
    pki: Pki,
    monkeypatch: pytest.MonkeyPatch,
    error: type[Exception] | None,
    subindication: str,
) -> None:
    """pyHanko folds these causes into CERTIFICATE_CHAIN_GENERAL_FAILURE; ETSI does not."""
    signed, _ = _sign(pki, minimal_pdf())

    async def second_look(self: CertificateValidator, usage: set[str]) -> None:
        if error is not None:
            raise error.__new__(error)

    monkeypatch.setattr(CertificateValidator, "async_validate_usage", second_look)
    [report] = verify_pdf(signed, pki.store, online=False).signatures
    assert report.subindication == subindication


@pytest.mark.parametrize(
    ("key_size", "digest", "indication"),
    [
        (2048, "sha256", Indication.TOTAL_PASSED),
        (2048, "sha1", Indication.INDETERMINATE),
        (1024, "sha256", Indication.INDETERMINATE),
    ],
    ids=["rsa2048-sha256", "sha1", "rsa1024"],
)
def test_obsolete_algorithms_are_not_accepted(
    pki: Pki, key_size: int, digest: str, indication: Indication
) -> None:
    """ACR-18 (guía de INDECOPI, anexo 1): SHA-1, MD5 and RSA below 2048 bits never pass."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    leaf = pki.leaf(f"FIRMANTE RSA{key_size} {digest}", key=key)
    registry = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    registry.register(to_asn1(pki.ca))
    signer = signers.SimpleSigner(
        signing_cert=to_asn1(leaf), signing_key=asn1_key(key), cert_registry=registry
    )
    metadata = signers.PdfSignatureMetadata(
        field_name="Firma", md_algorithm=digest, subfilter=SigSeedSubFilter.PADES
    )
    data = signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(minimal_pdf())), metadata, signer=signer
    ).getvalue()
    [report] = verify_pdf(
        data, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
    ).signatures
    assert report.indication is indication
    if indication is Indication.INDETERMINATE:
        assert report.subindication == "CRYPTO_CONSTRAINTS_FAILURE"


def test_ocsp_answer_dated_after_now_is_accepted(pki: Pki) -> None:
    """Validating now tolerates responses produced while it ran (R-17). At a past moment
    pyHanko does not apply "too recent" at all (ETSI EN 319 102-1 §5.2.5.4)."""
    signed, leaf = _sign(pki, minimal_pdf())
    # pki.ocsp dates thisUpdate 5 minutes before ``at``: here, 2 minutes after now.
    later = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=7)
    [report] = verify_pdf(
        signed,
        pki.store,
        online=False,
        ocsp_responses=[pki.ocsp(leaf, at=later)],
        crls=[pki.arl()],
    ).signatures
    assert report.indication is Indication.TOTAL_PASSED


@pytest.mark.parametrize("stage", ["_adobe_revinfo", "_validate_timestamp", "_diagnose_chain"])
def test_hostile_cms_past_the_digest_is_a_format_failure(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    """A CMS that breaks pyHanko or asn1crypto after the digest is still an ETSI result
    (TOTAL-FAILED/FORMAT_FAILURE), never an unexpected error (AM-05)."""
    from berigna.core.validation import pdf

    def broken(*_args: object) -> object:
        raise KeyError("hostile")

    monkeypatch.setattr(pdf, stage, broken)
    if stage == "_validate_timestamp":
        result = verify_pdf(pades(pki, "B-LTA")[0], pki.store, online=False)
        [stamp] = result.document_timestamps
        assert stamp.subindication == "FORMAT_FAILURE"
        return
    if stage == "_diagnose_chain":
        data, moment = _signed_with_revinfo(pki)[0], NOW + dt.timedelta(days=400)  # expired
        [report] = verify_pdf(data, pki.store, moment=moment, online=False).signatures
    else:
        [report] = verify_pdf(_signed_with_revinfo(pki)[0], pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "FORMAT_FAILURE"


# -- hostile time-stamps and any mutation (R-DES-18, DP-20 options A and E) ------------------------

UNKNOWN_DIGEST = "2.16.840.1.101.3.4.2.127"  # under the NIST hashes, assigned to none


def _with_unknown_tst_digest(pdf: bytes) -> bytes:
    """The signature time-stamp of the PDF with a digest algorithm pyHanko 0.25.1 does not
    know (same encoded length, so /Contents keeps its size): it raised AttributeError, and
    verify_pdf ended in ERR-000 hiding every signature of the file (R-DES-18)."""
    start = pdf.index(b"/Contents <") + len(b"/Contents <")
    end = pdf.index(b">", start)
    info = cms.ContentInfo.load(bytes.fromhex(pdf[start:end].decode()))
    attributes = info["content"]["signer_infos"][0]["unsigned_attrs"]
    stamp = next(a for a in attributes if a["type"].native == "signature_time_stamp_token")
    stamp["values"][0]["content"]["signer_infos"][0]["digest_algorithm"]["algorithm"] = (
        UNKNOWN_DIGEST
    )
    contents = info.dump(force=True).hex().encode().ljust(end - start, b"0")
    assert len(contents) == end - start
    return pdf[:start] + contents + pdf[end:]


def test_a_timestamp_with_an_unknown_digest_is_a_format_failure(pki: Pki) -> None:
    data, _ = pades(pki, "B-T")
    [report] = verify_pdf(_with_unknown_tst_digest(data), pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "FORMAT_FAILURE"


@dataclass(frozen=True)
class _Lta:
    data: bytes
    contents: tuple[int, int]  # the hex of /Contents, not signed
    signed_revision: int  # bytes covered by the signature; the DSS and the stamp come after


@pytest.fixture(scope="module")
def lta_pdf(pki: Pki) -> _Lta:
    """Parsed once: the property test runs 150 times (review of the increment 8)."""
    data = pades(pki, "B-LTA")[0]
    start = data.index(b"/Contents <") + len(b"/Contents <")
    signature = next(iter(PdfFileReader(io.BytesIO(data)).embedded_signatures))
    _, _, start2, length2 = (int(n) for n in signature.byte_range)
    return _Lta(data, (start, data.index(b">", start)), start2 + length2)


@settings(max_examples=150, deadline=None)
@given(position=st.integers(min_value=0), byte=st.integers(0, 255), inside=st.booleans())
def test_any_mutation_of_a_pdf_is_a_result_or_a_reading_error(
    pki: Pki, lta_pdf: _Lta, position: int, byte: int, inside: bool
) -> None:
    """A PDF B-LTA with any byte changed, half of them inside the CMS of the signature: an
    ETSI result or ERR-401, never an unexpected exception (AM-05). A change of the signed
    bytes (the signed revision, outside /Contents) is never TOTAL-PASSED."""
    data, (start, end) = lta_pdf.data, lta_pdf.contents
    index = start + position % (end - start) if inside else position % len(data)
    if inside:
        byte = b"0123456789abcdef"[byte % 16]
    mutated = data[:index] + bytes([byte]) + data[index + 1 :]
    try:
        reports = verify_pdf(mutated, pki.store, online=False).signatures
    except UnreadableDocumentError:
        return
    for report in reports:
        assert isinstance(report.indication, Indication)
    signed_bytes = index < lta_pdf.signed_revision and not start <= index < end
    if signed_bytes and mutated != data and reports:
        assert reports[0].indication is not Indication.TOTAL_PASSED


def test_a_damaged_dss_is_a_reading_error(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    """A /DSS entry that is not a stream (NullObject) raised AttributeError: ERR-401."""
    from berigna.core.validation import pdf as module

    def broken(*_args: object) -> object:
        raise AttributeError("'NullObject' object has no attribute 'data'")

    monkeypatch.setattr(module, "_dss_contents", broken)
    with pytest.raises(UnreadableDocumentError):
        verify_pdf(pades(pki, "B-LT")[0], pki.store, online=False)


def test_an_unreadable_signing_time_is_a_format_failure(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pyHanko reads /M lazily: a damaged date fails past the digest (mutation tests)."""

    def broken(_self: object) -> object:
        raise TypeError("cannot use a string pattern on a bytes-like object")

    monkeypatch.setattr(EmbeddedPdfSignature, "self_reported_timestamp", property(broken))
    [report] = verify_pdf(pades(pki, "B-T")[0], pki.store, online=False).signatures
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "FORMAT_FAILURE")


def test_a_signer_certificate_with_a_mutated_version_is_a_format_failure(pki: Pki) -> None:
    """cryptography's InvalidVersion is not a ValueError (review of the increment 8)."""
    data, _ = pades(pki, "B-T")
    start = data.index(b"/Contents <") + len(b"/Contents <")
    end = data.index(b">", start)
    contents = data[start:end].replace(b"A003020102", b"A003020107")
    assert contents != data[start:end]
    mutated = data[:start] + contents + data[end:]
    [report] = verify_pdf(mutated, pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_FAILED
