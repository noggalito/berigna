# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Verification of the signatures in a PDF (RF-050, RF-053, RF-055), first increment.

Each signature gets an ETSI EN 319 102-1 indication from pyHanko's AdES *basic* validation
process (§5.3): integrity, signer certificate, chain up to the trust store and revocation.
Revocation data comes from the document first (DSS, the Adobe ``revocationInfoArchival``
attribute of legacy ``adbe.pkcs7.detached`` signatures, certificates in the CMS) and, when
``online``, from OCSP and from the CRLs of the CAs. The CRL of an end-entity certificate is
never downloaded: for the DNIe it weighs ~109 MB (RF-063).

Separately from the indication, each signature reports which revision it covers and how the
document changed afterwards (RF-055), with pyHanko's difference analysis. A change that cannot
be classified as harmless (form filling, annotations, LTV data) is reported as ``OTHER``.

Not in this increment: time-stamps. Signature time-stamps are not evaluated yet (B-T and above
are validated as basic signatures) and document time-stamps are listed in
:attr:`PdfVerification.pending`, never silently dropped.

Like :func:`~berigna.core.validation.check_signer`, :func:`verify_pdf` runs its own asyncio
event loop: call it from a worker thread.
"""

import asyncio
import datetime as dt
import enum
import io
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from asn1crypto import cms
from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.ades.report import AdESFailure, AdESIndeterminate, AdESPassed
from pyhanko.sign.diff_analysis import ModificationLevel, SuspiciousModification
from pyhanko.sign.validation import ades
from pyhanko.sign.validation.errors import SignatureValidationError, ValidationInfoReadingError
from pyhanko.sign.validation.ltv import retrieve_adobe_revocation_info
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko.sign.validation.policy_decl import (
    LocalKnowledge,
    RevinfoOnlineFetchingRule,
    RevocationInfoGatheringSpec,
    SignatureValidationSpec,
)
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.errors import CRLFetchError
from pyhanko_certvalidator.fetchers.api import CRLFetcher, FetcherBackend, Fetchers
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_certvalidator.revinfo.archival import CRLContainer, OCSPContainer

from berigna.core.errors import UnreadableDocumentError
from berigna.core.trust import TrustStore
from berigna.core.validation.preflight import _to_asn1, _to_cryptography

_VERIFICATION_POLICY = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
    intermediate_ca_cert_rule=RevocationCheckingRule.CRL_REQUIRED,
)


class Indication(enum.Enum):
    """Main indication of ETSI EN 319 102-1 §5.1.3."""

    TOTAL_PASSED = "TOTAL-PASSED"
    TOTAL_FAILED = "TOTAL-FAILED"
    INDETERMINATE = "INDETERMINATE"


class Modifications(enum.Enum):
    """What changed in the document after the revision a signature covers (RF-055)."""

    NONE = "none"
    LTA_UPDATES = "lta-updates"  # validation data and document time-stamps only
    FORM_FILLING = "form-filling"
    ANNOTATIONS = "annotations"
    OTHER = "other"  # anything else, including changes pyHanko flags as suspicious


@dataclass(frozen=True)
class PdfSignatureReport:
    field_name: str
    indication: Indication
    subindication: str | None  # ETSI name, e.g. "HASH_FAILURE"; None when TOTAL-PASSED
    signer: x509.Certificate | None
    claimed_signing_time: dt.datetime | None  # /M of the signature dictionary, not certified
    subfilter: str
    covers_whole_document: bool
    modifications: Modifications
    signed_revision_length: int  # data[:signed_revision_length] is the version that was signed

    @property
    def document_unchanged_since_signing(self) -> bool:
        return self.modifications in (Modifications.NONE, Modifications.LTA_UPDATES)


@dataclass(frozen=True)
class PdfVerification:
    signatures: tuple[PdfSignatureReport, ...]
    pending: tuple[str, ...]  # field names of document time-stamps, not evaluated yet
    moment: dt.datetime


class _CaOnlyCrlFetcher(CRLFetcher):
    """Fetches CRLs for CA certificates only; end-entity CRLs can be huge (RF-063)."""

    def __init__(self, inner: CRLFetcher) -> None:
        self._inner = inner

    async def fetch(
        self, cert: Any, *, use_deltas: Any = None
    ) -> Iterable[asn1_crl.CertificateList]:
        if not isinstance(cert, asn1_x509.Certificate) or not cert.ca:
            raise CRLFetchError("CRLs of end-entity certificates are never downloaded")
        return await self._inner.fetch(cert, use_deltas=use_deltas)

    def fetched_crls(self) -> Iterable[asn1_crl.CertificateList]:
        return self._inner.fetched_crls()

    def fetched_crls_for_cert(self, cert: Any) -> Iterable[asn1_crl.CertificateList]:
        return self._inner.fetched_crls_for_cert(cert)


class _VerificationFetcherBackend(FetcherBackend):
    def __init__(self, timeout: float) -> None:
        self._inner = RequestsFetcherBackend(per_request_timeout=timeout)  # type: ignore[no-untyped-call]

    def get_fetchers(self) -> Fetchers:
        fetchers = self._inner.get_fetchers()
        return Fetchers(
            ocsp_fetcher=fetchers.ocsp_fetcher,
            crl_fetcher=_CaOnlyCrlFetcher(fetchers.crl_fetcher),
            cert_fetcher=fetchers.cert_fetcher,
        )


def _dss_contents(reader: PdfFileReader) -> tuple[list[Any], list[Any], list[Any]]:
    """Certificates, OCSP responses and CRLs of the Document Security Store, if any."""
    try:
        dss = reader.root["/DSS"]
    except KeyError:
        return [], [], []

    def streams(key: str) -> list[bytes]:
        return [ref.get_object().data for ref in dss.get(key, [])]

    return (
        [asn1_x509.Certificate.load(d) for d in streams("/Certs")],
        [asn1_ocsp.OCSPResponse.load(d) for d in streams("/OCSPs")],
        [asn1_crl.CertificateList.load(d) for d in streams("/CRLs")],
    )


def _adobe_revinfo(signed_data: cms.SignedData) -> tuple[list[Any], list[Any]]:
    try:
        ocsps, crls = retrieve_adobe_revocation_info(signed_data["signer_infos"][0])
    except ValidationInfoReadingError:
        return [], []
    return list(ocsps), list(crls)


def _modifications(integrity: dict[str, Any]) -> Modifications:
    diff = integrity.get("diff_result")
    if isinstance(diff, SuspiciousModification) or not integrity.get("docmdp_ok", True):
        return Modifications.OTHER
    level = diff.modification_level if diff is not None else ModificationLevel.NONE
    return {
        ModificationLevel.NONE: Modifications.NONE,
        ModificationLevel.LTA_UPDATES: Modifications.LTA_UPDATES,
        ModificationLevel.FORM_FILLING: Modifications.FORM_FILLING,
        ModificationLevel.ANNOTATIONS: Modifications.ANNOTATIONS,
    }.get(level, Modifications.OTHER)


def _indication(subindic: Any) -> tuple[Indication, str | None]:
    if isinstance(subindic, AdESPassed):
        return Indication.TOTAL_PASSED, None
    if isinstance(subindic, AdESFailure):
        return Indication.TOTAL_FAILED, subindic.name
    if isinstance(subindic, AdESIndeterminate):
        return Indication.INDETERMINATE, subindic.name
    raise TypeError(f"unexpected AdES subindication {subindic!r}")  # pragma: no cover


def _failed_format(sig: EmbeddedPdfSignature, subfilter: str) -> PdfSignatureReport:
    """A signature whose structure cannot be processed: ETSI TOTAL-FAILED/FORMAT_FAILURE."""
    return PdfSignatureReport(
        field_name=sig.field_name,
        indication=Indication.TOTAL_FAILED,
        subindication="FORMAT_FAILURE",
        signer=None,
        claimed_signing_time=None,
        subfilter=subfilter,
        covers_whole_document=False,
        modifications=Modifications.OTHER,
        signed_revision_length=0,
    )


def _verify_signature(
    sig: EmbeddedPdfSignature,
    store: TrustStore,
    dss: tuple[list[Any], list[Any], list[Any]],
    timing: ValidationTimingInfo,
    online: bool,
    timeout: float,
) -> PdfSignatureReport:
    subfilter = str(sig.sig_object.get("/SubFilter", ""))
    try:
        sig.compute_integrity_info()  # type: ignore[no-untyped-call]
        integrity = sig.summarise_integrity_info()
        digest = sig.compute_digest()
        *_, start2, len2 = (int(n) for n in sig.byte_range)
    except (PdfError, SignatureValidationError, ValueError, KeyError, TypeError):
        return _failed_format(sig, subfilter)

    coverage = integrity.get("coverage", SignatureCoverageLevel.UNCLEAR)
    if coverage < SignatureCoverageLevel.ENTIRE_REVISION:
        # The byte range does not span a whole revision: signature wrapping (AM-05).
        return _failed_format(sig, subfilter)

    dss_certs, dss_ocsps, dss_crls = dss
    adobe_ocsps, adobe_crls = _adobe_revinfo(sig.signed_data)
    knowledge = LocalKnowledge(
        known_certs=[_to_asn1(c) for c in store.intermediates] + dss_certs,
        known_ocsps=[c for o in dss_ocsps + adobe_ocsps for c in OCSPContainer.load_multi(o)],
        known_crls=[CRLContainer(c) for c in dss_crls + adobe_crls],
    )
    spec = SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(trust_roots=[_to_asn1(c) for c in store.roots]),
            revinfo_policy=CertRevTrustPolicy(_VERIFICATION_POLICY),
        ),
        revinfo_gathering_policy=RevocationInfoGatheringSpec(
            online_fetching_rule=(
                RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH
                if online
                else RevinfoOnlineFetchingRule.LOCAL_ONLY
            ),
            fetcher_backend=_VerificationFetcherBackend(timeout),
        ),
        local_knowledge=knowledge,
        key_usage_settings=KeyUsageConstraints(key_usage={"non_repudiation"}),
    )
    result = asyncio.run(
        ades.ades_basic_validation(sig.signed_data, spec, timing_info=timing, raw_digest=digest)
    )
    indication, subindication = _indication(result.ades_subindic)
    return PdfSignatureReport(
        field_name=sig.field_name,
        indication=indication,
        subindication=subindication,
        signer=_to_cryptography(sig.signer_cert),
        claimed_signing_time=sig.self_reported_timestamp,
        subfilter=subfilter,
        covers_whole_document=coverage == SignatureCoverageLevel.ENTIRE_FILE,
        modifications=_modifications(integrity),
        signed_revision_length=start2 + len2,
    )


def verify_pdf(
    data: bytes,
    store: TrustStore,
    *,
    moment: dt.datetime | None = None,
    online: bool = True,
    timeout: float = 10.0,
) -> PdfVerification:
    """Verify every signature in ``data`` at ``moment`` (now by default).

    Raises :class:`~berigna.core.errors.UnreadableDocumentError` when ``data`` is not a PDF
    that can be parsed. A PDF without signatures gives an empty report.
    """
    when = moment or dt.datetime.now(dt.UTC)
    timing = ValidationTimingInfo(
        validation_time=when, best_signature_time=when, point_in_time_validation=moment is not None
    )
    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        embedded = list(reader.embedded_signatures)
        dss = _dss_contents(reader)
    except (PdfError, ValueError, KeyError, TypeError) as exc:
        raise UnreadableDocumentError(f"cannot read this PDF: {exc}") from exc

    reports: list[PdfSignatureReport] = []
    pending: list[str] = []
    for sig in embedded:
        if sig.sig_object_type == "/DocTimeStamp":
            pending.append(sig.field_name)
            continue
        reports.append(_verify_signature(sig, store, dss, timing, online, timeout))
    return PdfVerification(signatures=tuple(reports), pending=tuple(pending), moment=when)
