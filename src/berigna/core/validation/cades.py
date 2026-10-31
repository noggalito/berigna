# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verification of CAdES signatures, ``.p7s`` detached and ``.p7m`` enveloping (RF-051).

Each ``SignerInfo`` of the CMS gets an ETSI EN 319 102-1 indication from pyHanko's AdES
validation on the bare ``SignedData``: the *basic* process (§5.3) for signatures without a
signature time-stamp, and the *with time* process (§5.5) for those that carry the
``signature-time-stamp`` attribute, where the TSA token is the proof of existence. Trust and
revocation data come first from the file itself (the certificates in
``SignedData.certificates``, the CRLs and the OCSP responses in ``crls``, as
``id-ri-ocsp-response``, RFC 5940) and, when ``online``, from the services, with the same
rules as the PDF verifier (RF-063: never the CRL of a final certificate).

Every time-stamp gets its own indication (RF-053): the signature time-stamp, and the
``archive-time-stamp-v3`` of B-LTA, validated on its own. The archive time-stamp covers three
pieces (EN 319 122-1 §5.5.2-3): the token itself carries its own ``ats-hash-index-v3``, and
three things get compared against it:

1. the candidates of the index (certificates, revocation data, unsigned attributes) with the
   values of the CMS as they stand *now*; a difference means the CMS changed after the
   archive time-stamp was created: TOTAL-FAILED/HASH_FAILURE;
2. the imprint itself: the content type, the ``message-digest`` of the signed attributes, the
   fields of the ``SignerInfo`` and the index; a difference means a modified ``SignerInfo``;
3. the stamp token chain, revocation data and validity.

Content: the caller passes ``content`` (the file a ``.p7s`` signs, RF-051); for a ``.p7m``,
:func:`cades_content` extracts the encapsulated one (it is returned in
``CadesVerification.content``). A detached signature without content cannot be checked for
integrity: that is an error, :class:`~berigna.core.errors.UnreadableSignatureError`.

Every parse or cryptography exception of asn1crypto and pyHanko is translated (AM-05): an
unreadable CMS raises the error (ERR-402) and one broken ``SignerInfo`` gives
TOTAL-FAILED/FORMAT_FAILURE, never an "unexpected error". Like the PDF verifier, this runs
its own asyncio event loop: call it from a worker thread.
"""

import asyncio
import datetime as dt
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asn1crypto import cms, core
from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from cryptography import x509
from pyhanko.sign.general import extract_certificate_info, find_unique_cms_attribute
from pyhanko.sign.validation import ades, generic_cms
from pyhanko.sign.validation.policy_decl import SignatureValidationSpec
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo

from berigna.core.certs import to_cryptography
from berigna.core.errors import UnreadableSignatureError
from berigna.core.formats.cades import (
    OID_ARCHIVE_TIME_STAMP_V3,
    OID_ATS_HASH_INDEX_V3,
    AtsHashIndexV3,
    CadesPackaging,
    signer_certificate,
)
from berigna.core.trust import TrustStore
from berigna.core.validation.preflight import time_tolerance
from berigna.core.validation.spec import (
    GENERIC_CHAIN_FAILURE,
    MALFORMED,
    Context,
    Indication,
    TimestampReport,
    diagnose_chain,
    indication,
    timestamp_report,
    validate_timestamp,
    validation_spec,
)

__all__ = [
    "CadesSignatureReport",
    "CadesVerification",
    "cades_content",
    "verify_cades",
]

# Archive time-stamps older than the v3 of EN 319 122-1; their attribute values never take
# part in the ats-hash-index of another archive time-stamp (§5.5.2).
_ARCHIVE_TIMESTAMPS = frozenset(
    ("1.2.840.113549.1.9.16.2.48", "1.2.840.113549.1.9.16.2.49", OID_ARCHIVE_TIME_STAMP_V3)
)
# The fields of the ``SignerInfo`` that the archive time-stamp v3 covers (§5.5.2).
_SIGNER_FIELDS = (
    "version",
    "sid",
    "digest_algorithm",
    "signed_attrs",
    "signature_algorithm",
    "signature",
)


@dataclass(frozen=True)
class CadesSignatureReport:
    """One ``SignerInfo`` of the CAdES (RF-053)."""

    packaging: CadesPackaging
    indication: Indication
    subindication: str | None  # ETSI name, e.g. "HASH_FAILURE"; None when TOTAL-PASSED
    signer: x509.Certificate | None
    claimed_signing_time: dt.datetime | None  # the ``signingTime`` attribute, not certified
    timestamp: TimestampReport | None  # signature time-stamp (B-T and above)
    archive_timestamps: tuple[TimestampReport, ...]  # archive-time-stamps (B-LTA)


@dataclass(frozen=True)
class CadesVerification:
    signatures: tuple[CadesSignatureReport, ...]
    content: bytes | None  # of an enveloping ``.p7m``; None for a detached ``.p7s``
    moment: dt.datetime


def signed_data_of(raw: bytes) -> cms.SignedData:
    """The ``SignedData`` of the CMS, or the reading error (ERR-402). Other CMS content
    types, such as an ``enveloped-data`` with encryption, are not CAdES (SPK-03)."""
    try:
        info = cms.ContentInfo.load(raw)
        signed_data: cms.SignedData = info["content"]
        if info["content_type"].native != "signed_data":
            raise ValueError(f"{info['content_type'].native} is not signed-data")
    except Exception as error:
        raise UnreadableSignatureError(f"cannot read this CMS: {error}") from error
    return signed_data


def cades_content(raw: bytes) -> bytes | None:
    """The encapsulated content of a ``.p7m`` (RF-051); ``None`` for a detached ``.p7s``."""
    signed_data = signed_data_of(raw)
    content = signed_data["encap_content_info"]["content"]
    return None if isinstance(content, core.Void) else bytes(content)


def _unsigned(signer_info: cms.SignerInfo) -> list[cms.CMSAttribute]:
    attributes = signer_info["unsigned_attrs"]
    return [] if isinstance(attributes, core.Void) else list(attributes)


def _certificates(signed_data: cms.SignedData) -> list[x509.Certificate]:
    """The X.509 certificates of ``SignedData.certificates``; attribute certificates stay
    out: the AdES process handles the signer attributes on its own."""
    if isinstance(signed_data["certificates"], core.Void):
        return []
    return [
        to_cryptography(choice.chosen)
        for choice in signed_data["certificates"]
        if choice.name == "certificate"
    ]


def _ocsp_crls(signed_data: cms.SignedData) -> tuple[list[Any], list[Any]]:
    """The OCSP responses (``id-ri-ocsp-response``, RFC 5940) and the CRLs that the CAdES
    embeds in ``SignedData.crls``."""
    if isinstance(signed_data["crls"], core.Void):
        return [], []
    ocsps: list[Any] = []
    crls: list[Any] = []
    for choice in signed_data["crls"]:
        if choice.name == "crl":
            crls.append(choice.chosen)
        elif choice.chosen["other_rev_info_format"].native == "ocsp_response":
            ocsps.append(choice.chosen["other_rev_info"])
    return ocsps, crls


def _archive_tokens(signer_info: cms.SignerInfo) -> list[tuple[cms.SignedData, AtsHashIndexV3]]:
    """Each ``archive-time-stamp-v3`` attribute and the ``ats-hash-index-v3`` inside its own
    token, kept from the moment the stamp was made (EN 319 122-1 §5.5.2). An archive
    time-stamp without an index is a broken signature: the caller reports a format failure."""
    tokens: list[tuple[cms.SignedData, AtsHashIndexV3]] = []
    for attribute in _unsigned(signer_info):
        if attribute["type"].native != OID_ARCHIVE_TIME_STAMP_V3:
            continue
        # asn1crypto does not know these attributes: the value is an ``Any``, so the
        # ContentInfo inside has to be loaded explicitly (from its own dump).
        token: cms.SignedData = cms.ContentInfo.load(attribute["values"][0].dump())["content"]
        index_attr = next(
            (
                a
                for a in _unsigned(token["signer_infos"][0])
                if a["type"].native == OID_ATS_HASH_INDEX_V3
            ),
            None,
        )
        if index_attr is None:
            raise ValueError("the archive time-stamp has no ats-hash-index-v3")
        tokens.append((token, AtsHashIndexV3.load(index_attr["values"][0].dump())))
    return tokens


def _indexed_pieces(
    signed_data: cms.SignedData, signer_info: cms.SignerInfo, algorithm: str
) -> dict[str, list[bytes]]:
    """What the ``ats-hash-index-v3`` covers, hashed with its own algorithm, from the values
    of the CMS as they stand now: the certificates, the CRLs (and OCSP responses), the values
    of the unsigned attributes without archive time-stamps (EN 319 122-1 §5.5.2)."""
    unsigned = [a for a in _unsigned(signer_info) if a["type"].native not in _ARCHIVE_TIMESTAMPS]
    certificates = signed_data["certificates"]
    crls = signed_data["crls"]
    pieces = {
        "certificates": []
        if isinstance(certificates, core.Void)
        else [c.dump() for c in certificates],
        "crls": [] if isinstance(crls, core.Void) else [c.dump() for c in crls],
        "unsigned_attrs": [
            a["type"].dump() + value.dump() for a in unsigned for value in a["values"]
        ],
    }
    return {
        name: [hashlib.new(algorithm, piece).digest() for piece in values]
        for name, values in pieces.items()
    }


def _archive_imprint(
    signed_data: cms.SignedData, signer_info: cms.SignerInfo, index: AtsHashIndexV3
) -> bytes:
    """The raw imprint that the archive time-stamp token covers: the content type, the
    ``message-digest`` of the signed attributes, the fields of the ``SignerInfo``, and the
    index exactly as it stands in the token (EN 319 122-1 §5.5.3)."""
    content_digest: bytes = find_unique_cms_attribute(  # type: ignore[no-untyped-call]
        signer_info["signed_attrs"], "message_digest"
    ).native
    fields = b"".join(signer_info[name].dump() for name in _SIGNER_FIELDS)
    concatenated = (
        signed_data["encap_content_info"]["content_type"].dump()
        + content_digest
        + fields
        + index.dump()
    )
    return bytes(concatenated)


def _index_of_current_cms(
    index: AtsHashIndexV3, signed_data: cms.SignedData, signer_info: cms.SignerInfo
) -> bool:
    """Whether the pieces that the index covers still match the CMS as it stands (the first
    check above): one difference in any of the three lists invalidates the coverage."""
    algorithm = index["hash_ind_algorithm"]["algorithm"].native
    expected = {
        "certificates": [v.native for v in index["certificates_hash_index"]],
        "crls": [v.native for v in index["crls_hash_index"]],
        "unsigned_attrs": [v.native for v in index["unsigned_attr_values_hash_index"]],
    }
    return expected == _indexed_pieces(signed_data, signer_info, algorithm)


def _validate_archive(
    token: cms.SignedData,
    index: AtsHashIndexV3,
    signed_data: cms.SignedData,
    signer_info: cms.SignerInfo,
    spec: SignatureValidationSpec,
    context: Context,
) -> TimestampReport:
    """§5.4 for one archive time-stamp, with its integrity check against the CMS: if the
    CMS is no longer what the index covers, the token stays valid but the coverage does not,
    and the report is TOTAL-FAILED/HASH_FAILURE (RF-053)."""
    try:
        if not _index_of_current_cms(index, signed_data, signer_info):
            return TimestampReport(Indication.TOTAL_FAILED, "HASH_FAILURE", None, None)
        algorithm = index["hash_ind_algorithm"]["algorithm"].native
        imprint = _archive_imprint(signed_data, signer_info, index)
        result = validate_timestamp(
            token, hashlib.new(algorithm, imprint).digest(), spec, context.timing
        )
    except MALFORMED:
        return TimestampReport(Indication.TOTAL_FAILED, "FORMAT_FAILURE", None, None)
    return timestamp_report(result)


def _signature_timestamp_report(
    signer_info: cms.SignerInfo, spec: SignatureValidationSpec, context: Context
) -> TimestampReport:
    """§5.4 for the ``signature-time-stamp`` attribute of one signature."""
    tst = generic_cms.extract_tst_data(signer_info, signed=False)
    imprint: bytes | None = generic_cms.compute_signature_tst_digest(signer_info)
    if tst is None or imprint is None:
        raise ValueError("the signature has no readable time-stamp")
    return timestamp_report(validate_timestamp(tst, imprint, spec, context.timing))


def _failed_format(packaging: CadesPackaging) -> CadesSignatureReport:
    """One ``SignerInfo`` that cannot be processed: ETSI TOTAL-FAILED/FORMAT_FAILURE."""
    return CadesSignatureReport(
        packaging=packaging,
        indication=Indication.TOTAL_FAILED,
        subindication="FORMAT_FAILURE",
        signer=None,
        claimed_signing_time=None,
        timestamp=None,
        archive_timestamps=(),
    )


def _verify_signer_info(
    signed_data: cms.SignedData,
    signer_info: cms.SignerInfo,
    content: bytes,
    context: Context,
    packaging: CadesPackaging,
    spec: SignatureValidationSpec,
) -> CadesSignatureReport:
    """The ETSI validation of one ``SignerInfo`` (§5.3 or §5.5) and of its time-stamps."""
    try:
        digest_algorithm: str = signer_info["digest_algorithm"]["algorithm"].native
        # An enveloping CMS computes the digest over its encapsulated content (pyHanko
        # refuses a raw digest when the content is embedded, §5.3 of RFC 5652); a detached
        # one digests the content given by the caller.
        raw_digest = (
            None
            if packaging is CadesPackaging.ENVELOPING
            else hashlib.new(digest_algorithm, content).digest()
        )
        tst = generic_cms.extract_tst_data(signer_info, signed=False)
        ts_report: TimestampReport | None = None
        if tst is None:
            result: ades.AdESBasicValidationResult[Any] = asyncio.run(
                ades.ades_basic_validation(
                    signed_data, spec, timing_info=context.timing, raw_digest=raw_digest
                )
            )
        else:
            result = asyncio.run(
                ades.ades_with_time_validation(
                    signed_data, spec, timing_info=context.timing, raw_digest=raw_digest
                )
            )
            ts_report = _signature_timestamp_report(signer_info, spec, context)
        indicate, subindication = indication(result.ades_subindic)
        if subindication == GENERIC_CHAIN_FAILURE:
            # The same diagnosis as the PDF verifier: pyHanko folds causes ETSI
            # distinguishes (missing revocation data, expired CA, a service down...) into
            # one generic value (§5.2.6); with a time-stamp it stays there (§5.5 does not
            # fold the notice into the past) unless the failure is truly in the past.
            signer_cert = extract_certificate_info(signed_data).signer_cert
            subindication = diagnose_chain(signed_data, signer_cert, spec, context.timing)
        archive_reports = tuple(
            _validate_archive(token, index, signed_data, signer_info, spec, context)
            for token, index in _archive_tokens(signer_info)
        )
        claimed = generic_cms.extract_self_reported_ts(signer_info)
        signer = to_cryptography(signer_certificate(signed_data))
    except MALFORMED:
        # A hostile or broken CMS that pyHanko or asn1crypto cannot process: ETSI result.
        return _failed_format(packaging)
    return CadesSignatureReport(
        packaging=packaging,
        indication=indicate,
        subindication=subindication,
        signer=signer,
        claimed_signing_time=claimed,
        timestamp=ts_report,
        archive_timestamps=archive_reports,
    )


def verify_cades(
    signature: bytes,
    store: TrustStore,
    *,
    content: bytes | None = None,
    moment: dt.datetime | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    timeout: float = 10.0,
) -> CadesVerification:
    """Verify the CAdES in ``signature`` at ``moment`` (now by default).

    ``content`` is the file a detached ``.p7s`` signs (RF-051); for a ``.p7m`` written by
    berigna, the encapsulated content is used (and returned in ``verification.content``).
    ``ocsp_responses`` and ``crls`` (DER) add revocation data to what the CMS carries; with
    ``online`` the rest is fetched with the rules of RF-063.

    Raises :class:`~berigna.core.errors.UnreadableSignatureError` when the bytes are not a
    CMS, when the type is not ``signed_data``, or when a detached signature comes without
    ``content``.
    """
    when = moment or dt.datetime.now(dt.UTC)
    signed_data = signed_data_of(signature)
    encapsulated = signed_data["encap_content_info"]["content"]
    embedded: bytes | None = None if isinstance(encapsulated, core.Void) else bytes(encapsulated)
    packaging = CadesPackaging.ENVELOPING if embedded is not None else CadesPackaging.DETACHED
    checked = embedded if embedded is not None else content
    if checked is None:
        raise UnreadableSignatureError(
            "a detached CAdES needs the content it signs (RF-051): pass it as ``content``"
        )

    context = Context(
        store=store,
        extra_ocsps=[asn1_ocsp.OCSPResponse.load(response) for response in ocsp_responses],
        extra_crls=[asn1_crl.CertificateList.load(crl) for crl in crls],
        timing=ValidationTimingInfo(
            validation_time=when,
            best_signature_time=when,
            point_in_time_validation=moment is not None,
        ),
        tolerance=time_tolerance(moment),
        online=online,
        timeout=timeout,
    )
    own_ocsps, own_crls = _ocsp_crls(signed_data)
    spec = validation_spec(
        context,
        [*store.intermediates, *_certificates(signed_data)],
        [*own_ocsps, *context.extra_ocsps],
        [*own_crls, *context.extra_crls],
    )
    signer_infos = list(signed_data["signer_infos"])
    if not signer_infos:  # an empty CMS has no signature: ETSI has nothing to say about it
        raise UnreadableSignatureError("the CMS has no SignerInfo")
    return CadesVerification(
        signatures=tuple(
            _verify_signer_info(signed_data, signer_info, checked, context, packaging, spec)
            for signer_info in signer_infos
        ),
        content=embedded,
        moment=when,
    )
