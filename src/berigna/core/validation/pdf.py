# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verification of the signatures in a PDF (RF-050, RF-053, RF-055, RF-056).

Each signature gets an ETSI EN 319 102-1 indication from pyHanko's AdES validation: the *basic*
process (§5.3) for signatures without a time-stamp (B-B) and the process for signatures with
long-term validation material (§5.6.3) for those with a signature time-stamp (B-T and above).
The latter takes the proof of existence from the time-stamps and from the document time-stamps
that follow, so a signature whose certificate has since expired can still pass (RF-056).
Each check covers integrity, signer certificate, chain up to the trust store and revocation.
Revocation data comes from the document first (DSS, the Adobe ``revocationInfoArchival``
attribute of legacy ``adbe.pkcs7.detached`` signatures, certificates in the CMS) and, when
``online``, from OCSP and from the CRLs of the CAs, with the rules of
:mod:`berigna.core.net.fetchers` (never the CRL of an end-entity certificate, RF-063).

Separately from the indication, each signature reports which revision it covers and how the
document changed afterwards (RF-055), with pyHanko's difference analysis. A change that cannot
be classified as harmless (form filling, annotations, LTV data) is reported as ``OTHER``.

Signature time-stamps and document time-stamps get their own indication (§5.4), reported
separately from the signature (RF-053): an invalid archive time-stamp is shown even when the
signature passes. Time-stamping units are validated against the same trust store.

The ETSI machinery shared with the CAdES verifier (indications, time-stamp reports, chain
diagnosis and the validation settings) lives in :mod:`berigna.core.validation.spec`; here
stays what only exists in a PDF: the Document Security Store, the revisions (RF-055) and the
legacy Adobe attribute.

Like :func:`~berigna.core.validation.check_signer`, :func:`verify_pdf` runs its own asyncio
event loop: call it from a worker thread.
"""

import asyncio
import datetime as dt
import enum
import io
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asn1crypto import cms
from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel, SuspiciousModification
from pyhanko.sign.validation import ades, generic_cms
from pyhanko.sign.validation.errors import ValidationInfoReadingError
from pyhanko.sign.validation.ltv import retrieve_adobe_revocation_info
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    SignatureValidationSpec,
)
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo

from berigna.core.certs import to_cryptography
from berigna.core.errors import UnreadableDocumentError
from berigna.core.trust import TrustStore
from berigna.core.validation.preflight import time_tolerance
from berigna.core.validation.spec import (
    GENERIC_CHAIN_FAILURE,
    MALFORMED,
    Context,
    Indication,
    TimestampReport,
    indication,
    timestamp_report,
)
from berigna.core.validation.spec import diagnose_chain as _diagnose_cms_chain
from berigna.core.validation.spec import validation_spec as _spec_of

# Re-used names: the tests of hostile inputs patch the PDF steps by name (AM-05).
GENERIC_CHAIN_FAILURE = GENERIC_CHAIN_FAILURE
_MALFORMED = (PdfError, *MALFORMED)
_indication = indication


__all__ = [
    "Indication",
    "Modifications",
    "PdfSignatureReport",
    "PdfVerification",
    "TimestampReport",
    "verify_pdf",
]


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
    timestamp: TimestampReport | None = None  # signature time-stamp (B-T and above)

    @property
    def document_unchanged_since_signing(self) -> bool:
        return self.modifications in (Modifications.NONE, Modifications.LTA_UPDATES)


@dataclass(frozen=True)
class PdfVerification:
    signatures: tuple[PdfSignatureReport, ...]
    document_timestamps: tuple[TimestampReport, ...]
    moment: dt.datetime


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


def _spec(
    context: Context,
    dss: tuple[list[Any], list[Any], list[Any]],
    adobe: tuple[list[Any], list[Any]],
) -> SignatureValidationSpec:
    """The validation settings of one file: the certificates of the store and the document as
    known, and the revocation data of the document (DSS and Adobe) plus the caller's."""
    store = context.store
    dss_certs, dss_ocsps, dss_crls = dss
    ocsps = [*dss_ocsps, *adobe[0], *context.extra_ocsps]
    crls = [*dss_crls, *adobe[1], *context.extra_crls]
    return _spec_of(context, [*store.intermediates, *dss_certs], ocsps, crls)


def _validate_timestamp(
    tst: cms.SignedData, imprint: bytes, spec: SignatureValidationSpec, context: Context
) -> ades.AdESBasicValidationResult[Any]:
    """§5.4: a document time-stamp or a signature time-stamp validated on its own."""
    return asyncio.run(
        ades.ades_timestamp_validation(
            tst, spec, expected_tst_imprint=imprint, timing_info=context.timing
        )
    )


def _timestamp_report(
    result: ades.AdESBasicValidationResult[Any], field_name: str | None = None
) -> TimestampReport:
    return timestamp_report(result, field_name)


def _diagnose_chain(
    sig: EmbeddedPdfSignature, spec: SignatureValidationSpec, context: Context
) -> str:
    """Name the ETSI subindication pyHanko folds into CERTIFICATE_CHAIN_GENERAL_FAILURE."""
    return _diagnose_cms_chain(sig.signed_data, sig.signer_cert, spec, context.timing)


def _validate_signature(
    sig: EmbeddedPdfSignature,
    digest: bytes,
    context: Context,
    dss: tuple[list[Any], list[Any], list[Any]],
) -> tuple[ades.AdESBasicValidationResult[Any], TimestampReport | None, SignatureValidationSpec]:
    """The ETSI validation proper: basic process, or the LTA one when the signature has a
    time-stamp."""
    timestamp: TimestampReport | None = None
    spec = _spec(context, dss, _adobe_revinfo(sig.signed_data))
    tst = sig.attached_timestamp_data
    tst_imprint = generic_cms.compute_signature_tst_digest(sig.signer_info)
    if tst is None or tst_imprint is None:
        result: ades.AdESBasicValidationResult[Any] = asyncio.run(
            ades.ades_basic_validation(
                sig.signed_data, spec, timing_info=context.timing, raw_digest=digest
            )
        )
    else:
        lta = asyncio.run(
            ades.ades_lta_validation(
                sig, PdfSignatureValidationSpec(spec), timing_info=context.timing
            )
        )
        # pyHanko leaves the time-stamp status out when it stops early; validate it alone then.
        ts_result = lta.signature_timestamp_status or _validate_timestamp(
            tst, tst_imprint, spec, context
        )
        result, timestamp = lta, _timestamp_report(ts_result)
    return result, timestamp, spec


def _verify_signature(
    sig: EmbeddedPdfSignature, context: Context, dss: tuple[list[Any], list[Any], list[Any]]
) -> PdfSignatureReport:
    subfilter = str(sig.sig_object.get("/SubFilter", ""))
    try:
        sig.compute_integrity_info()  # type: ignore[no-untyped-call]
        integrity = sig.summarise_integrity_info()
        digest = sig.compute_digest()
        *_, start2, len2 = (int(n) for n in sig.byte_range)
    except _MALFORMED:
        return _failed_format(sig, subfilter)

    coverage = integrity.get("coverage", SignatureCoverageLevel.UNCLEAR)
    if coverage < SignatureCoverageLevel.ENTIRE_REVISION:
        # The byte range does not span a whole revision: signature wrapping (AM-05).
        return _failed_format(sig, subfilter)

    try:
        result, timestamp, spec = _validate_signature(sig, digest, context, dss)
        indication, subindication = _indication(result.ades_subindic)
        if subindication == GENERIC_CHAIN_FAILURE and sig.attached_timestamp_data is None:
            # Basic process only: under the LTA process the cause may be in the past validation.
            subindication = _diagnose_chain(sig, spec, context)
    except _MALFORMED:
        # A hostile or broken CMS that pyHanko or asn1crypto cannot process past the digest.
        return _failed_format(sig, subfilter)
    return PdfSignatureReport(
        field_name=sig.field_name,
        indication=indication,
        subindication=subindication,
        signer=to_cryptography(sig.signer_cert),
        claimed_signing_time=sig.self_reported_timestamp,
        subfilter=subfilter,
        covers_whole_document=coverage == SignatureCoverageLevel.ENTIRE_FILE,
        modifications=_modifications(integrity),
        signed_revision_length=start2 + len2,
        timestamp=timestamp,
    )


def _verify_document_timestamp(
    sig: EmbeddedPdfSignature, context: Context, dss: tuple[list[Any], list[Any], list[Any]]
) -> TimestampReport:
    try:
        imprint = sig.compute_digest()
        result = _validate_timestamp(
            sig.signed_data, imprint, _spec(context, dss, ([], [])), context
        )
    except _MALFORMED:
        return TimestampReport(
            Indication.TOTAL_FAILED, "FORMAT_FAILURE", None, None, sig.field_name
        )
    return _timestamp_report(result, sig.field_name)


def verify_pdf(
    data: bytes,
    store: TrustStore,
    *,
    moment: dt.datetime | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    timeout: float = 10.0,
) -> PdfVerification:
    """Verify every signature in ``data`` at ``moment`` (now by default).

    ``ocsp_responses`` and ``crls`` (DER) add revocation data to what the document carries;
    with ``online`` the rest is fetched.

    Raises :class:`~berigna.core.errors.UnreadableDocumentError` when ``data`` is not a PDF
    that can be parsed. A PDF without signatures gives an empty report.
    """
    when = moment or dt.datetime.now(dt.UTC)
    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        embedded = list(reader.embedded_signatures)
        dss = _dss_contents(reader)
    except (PdfError, ValueError, KeyError, TypeError) as exc:
        raise UnreadableDocumentError(f"cannot read this PDF: {exc}") from exc

    context = Context(
        store=store,
        extra_ocsps=[asn1_ocsp.OCSPResponse.load(o) for o in ocsp_responses],
        extra_crls=[asn1_crl.CertificateList.load(c) for c in crls],
        timing=ValidationTimingInfo(
            validation_time=when,
            best_signature_time=when,
            point_in_time_validation=moment is not None,
        ),
        tolerance=time_tolerance(moment),
        online=online,
        timeout=timeout,
    )
    reports: list[PdfSignatureReport] = []
    stamps: list[TimestampReport] = []
    for sig in embedded:
        if sig.sig_object_type == "/DocTimeStamp":
            stamps.append(_verify_document_timestamp(sig, context, dss))
        else:
            reports.append(_verify_signature(sig, context, dss))
    return PdfVerification(
        signatures=tuple(reports), document_timestamps=tuple(stamps), moment=when
    )
