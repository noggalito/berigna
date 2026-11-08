# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verification of XAdES signatures, enveloped, enveloping and detached (RF-052).

signxml verifies XMLDSig but not XAdES, and pyHanko's AdES processes take a CMS: this module
runs the ETSI EN 319 102-1 processes itself, with the same building blocks as the CAdES
verifier (the validation spec, the X.509 validation of pyhanko-certvalidator, the time-stamp
validation of pyHanko):

1. Format (§5.2.2): ``SignedInfo``, ``SignatureValue`` and the ``QualifyingProperties`` that
   target the signature, with ``SignedProperties`` covered by a reference of type
   ``SignedProperties``. Otherwise TOTAL-FAILED/FORMAT_FAILURE.
2. Signing certificate (§5.2.3): the certificate whose digest is the first ``Cert`` of
   ``SigningCertificate`` or ``SigningCertificateV2``, among those of ``KeyInfo``,
   ``CertificateValues`` and the store; never the ``KeyValue``. Otherwise
   INDETERMINATE/NO_SIGNING_CERTIFICATE_FOUND.
3. Cryptographic verification (§5.2.7), in :mod:`berigna.core.validation.xmldsig`: every
   reference is dereferenced and transformed with an allow-list of transforms, and digested;
   then ``SignatureValue`` over the canonicalized ``SignedInfo``. A difference is
   TOTAL-FAILED/HASH_FAILURE or SIG_CRYPTO_FAILURE; SHA-1, MD5 and RSA under 2048 bits are
   INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE (ACR-18).
4. X.509 validation (§5.2.6) with the rules of the PDF and CAdES verifiers (RF-063), and the
   process *with time* (§5.5) when the signature carries a ``SignatureTimeStamp``.
5. Every time-stamp gets its own indication (RF-053): the signature time-stamp and each
   ``xades141:ArchiveTimeStamp``, whose imprint is recomputed from the signature as it stands
   (EN 319 132-1 §5.5.2): a signature changed after the archive time-stamp gives
   TOTAL-FAILED/HASH_FAILURE on the time-stamp, even if the signature stays valid.

XML Signature Wrapping (AM-06, CS-06): references are resolved strictly — an ``Id`` that
appears twice is a format failure, never "the first one" — and each report says what the
signature covers (:class:`SignedScope`), so that the interface can show it: a signature over
a part of the document is valid, but it does not vouch for the rest.

Like the other verifiers, this runs its own asyncio event loops: call it from a worker
thread.
"""

import asyncio
import base64
import binascii
import datetime as dt
import enum
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asn1crypto import cms
from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree
from pyhanko.sign.validation import generic_cms
from pyhanko.sign.validation.policy_decl import (
    SignatureValidationSpec,
    bootstrap_validation_data_handlers,
)
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo

from berigna.core.certs import to_asn1
from berigna.core.errors import UnreadableDocumentError, UnreadableSignatureError
from berigna.core.formats.xades import NS, XADES, XADES141, XadesPackaging, parse_document
from berigna.core.trust import TrustStore
from berigna.core.validation.preflight import time_tolerance
from berigna.core.validation.spec import (
    GENERIC_CHAIN_FAILURE,
    MALFORMED,
    Context,
    Indication,
    TimestampReport,
    diagnose_path,
    log_malformed,
    timestamp_report,
    validate_timestamp,
    validation_spec,
)
from berigna.core.validation.xmldsig import (
    C14N10,
    CANONICALIZATIONS,
    DS_OBJECT,
    DS_SIGNATURE,
    SIGNED_PROPERTIES,
    Octets,
    Result,
    by_id,
    c14n_of,
    check_references,
    check_signature_value,
    digest_name,
    format_failure,
    text_of,
    unique_by_id,
    weak_failure,
)

__all__ = [
    "SignedScope",
    "XadesSignatureReport",
    "XadesVerification",
    "verify_xades",
]


# The basic results that the signature time-stamp may still turn into a pass (§5.5.4),
# as pyHanko's process with time does for CAdES.
_FURTHER_WITH_TIME = frozenset(
    (
        None,
        "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
        "REVOKED_NO_POE",
        "REVOKED_CA_NO_POE",
        "TRY_LATER",
        "OUT_OF_BOUNDS_NO_POE",
    )
)
# What a hostile signature raises past the parser: MALFORMED and the XML-specific ones.
_UNREADABLE = (*MALFORMED, binascii.Error, etree.LxmlError)


class SignedScope(enum.Enum):
    """What the signature covers (AM-06): the interface shows it next to the result."""

    DOCUMENT = "document"  # the whole document the signature is in, except the signatures
    PART = "part"  # only some elements of the document: the rest is not signed
    OBJECT = "object"  # the content inside the signature (enveloping)
    EXTERNAL = "external"  # a file outside the signature (detached)


@dataclass(frozen=True)
class XadesSignatureReport:
    """One ``ds:Signature`` of the document (RF-053)."""

    packaging: XadesPackaging
    indication: Indication
    subindication: str | None  # ETSI name, e.g. "HASH_FAILURE"; None when TOTAL-PASSED
    signer: x509.Certificate | None
    claimed_signing_time: dt.datetime | None  # ``SigningTime``, not certified
    timestamp: TimestampReport | None  # signature time-stamp (B-T and above)
    archive_timestamps: tuple[TimestampReport, ...]  # xades141:ArchiveTimeStamp (B-LTA)
    scope: SignedScope | None  # None when the signature could not be read
    references: tuple[str, ...]  # the URIs of the signed data objects


@dataclass(frozen=True)
class XadesVerification:
    signatures: tuple[XadesSignatureReport, ...]
    moment: dt.datetime


# -- the signed properties and the signing certificate -------------------------------------


def _signed_properties(sig: etree._Element, tree: etree._ElementTree) -> etree._Element:
    """The ``SignedProperties`` of the ``QualifyingProperties`` that target ``sig``, which a
    reference of type ``SignedProperties`` must cover (otherwise the signing certificate
    would be an unsigned claim)."""
    identifier = sig.get("Id")
    qualifying = [
        q
        for q in sig.findall("ds:Object/xades:QualifyingProperties", NS)
        if identifier is not None and q.get("Target") == f"#{identifier}"
    ]
    if len(qualifying) != 1:
        raise format_failure("no QualifyingProperties that target the signature")
    signed = qualifying[0].find("xades:SignedProperties", NS)
    if signed is None:
        raise format_failure("no SignedProperties")
    covered = any(
        reference.get("Type") == SIGNED_PROPERTIES
        and (reference.get("URI") or "").startswith("#")
        and by_id(tree, (reference.get("URI") or "")[1:]) is signed
        for reference in sig.findall("ds:SignedInfo/ds:Reference", NS)
    )
    if not covered:
        raise format_failure("the SignedProperties are not signed")
    return signed


def _certificates_of(sig: etree._Element) -> list[x509.Certificate]:
    """The certificates the signature carries: ``KeyInfo`` and ``CertificateValues`` (also
    those of ``TimeStampValidationData``)."""
    values = [
        *sig.iterfind("ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS),
        *sig.iterfind(".//xades:EncapsulatedX509Certificate", NS),
    ]
    return [x509.load_der_x509_certificate(base64.b64decode(v.text or "")) for v in values]


def _signing_certificate(
    signed: etree._Element, candidates: Sequence[x509.Certificate]
) -> x509.Certificate:
    """The certificate named by the first ``Cert`` of ``SigningCertificate(V2)`` (EN 319
    132-1 §5.2.2). The digest of v1 is often SHA-1: it only identifies a certificate the
    signature already names, so it is accepted here."""
    cert = signed.find("xades:SignedSignatureProperties/xades:SigningCertificateV2/xades:Cert", NS)
    if cert is None:
        cert = signed.find(
            "xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert", NS
        )
    if cert is None:
        raise Result(
            Indication.INDETERMINATE, "NO_SIGNING_CERTIFICATE_FOUND", "no SigningCertificate"
        )
    name = digest_name(cert.find("xades:CertDigest/ds:DigestMethod", NS))
    expected = base64.b64decode(text_of(cert, "xades:CertDigest/ds:DigestValue"))
    for candidate in candidates:
        der = candidate.public_bytes(Encoding.DER)
        if hashlib.new(name, der).digest() == expected:
            return candidate
    raise Result(Indication.INDETERMINATE, "NO_SIGNING_CERTIFICATE_FOUND", "no certificate matches")


# -- time-stamps ----------------------------------------------------------------------------


def _token(element: etree._Element) -> tuple[cms.SignedData, str]:
    """The ``SignedData`` of an ``EncapsulatedTimeStamp`` and the hash of its imprint."""
    raw = base64.b64decode(text_of(element, "xades:EncapsulatedTimeStamp"))
    signed_data: cms.SignedData = cms.ContentInfo.load(raw)["content"]
    info = signed_data["encap_content_info"]["content"].parsed
    algorithm: str = info["message_imprint"]["hash_algorithm"]["algorithm"].native
    return signed_data, algorithm


def _timestamp_c14n(element: etree._Element) -> str:
    method = element.find("ds:CanonicalizationMethod", NS)
    algorithm = C14N10 if method is None else method.get("Algorithm", "")
    if algorithm not in CANONICALIZATIONS:
        raise ValueError(f"unsupported canonicalization {algorithm!r}")
    return algorithm


def _signature_timestamp(
    sig: etree._Element, element: etree._Element, spec: SignatureValidationSpec, context: Context
) -> TimestampReport:
    """§5.4 for ``SignatureTimeStamp``: over ``ds:SignatureValue`` (EN 319 132-1 §5.3)."""
    try:
        token, algorithm = _token(element)
        value = sig.find("ds:SignatureValue", NS)
        if value is None:
            raise ValueError("no SignatureValue")
        imprint = hashlib.new(algorithm, c14n_of(value, _timestamp_c14n(element))).digest()
        return timestamp_report(validate_timestamp(token, imprint, spec, context.timing))
    except Result as result:  # e.g. no EncapsulatedTimeStamp: only the time-stamp fails
        return TimestampReport(result.indication, result.subindication, None, None)
    except _UNREADABLE:
        return TimestampReport(Indication.TOTAL_FAILED, "FORMAT_FAILURE", None, None)


def _archive_octets(
    sig: etree._Element, archive: etree._Element, octets: Octets, algorithm: str
) -> bytes:
    """What ``xades141:ArchiveTimeStamp`` covers (EN 319 132-1 §5.5.2): the output of every
    reference, ``SignedInfo``, ``SignatureValue``, ``KeyInfo``, the unsigned signature
    properties that precede it and the ``ds:Object`` elements other than the one of
    ``QualifyingProperties``."""
    pieces = [
        octets.of(reference, final=algorithm)[0]
        for reference in sig.findall("ds:SignedInfo/ds:Reference", NS)
    ]
    for path in ("ds:SignedInfo", "ds:SignatureValue", "ds:KeyInfo"):
        element = sig.find(path, NS)
        if element is not None:
            pieces.append(c14n_of(element, algorithm))
    preceding: list[bytes] = []
    for element in archive.itersiblings(preceding=True):  # nearest first: reversed below
        if isinstance(element.tag, str):  # elements only, not comments
            preceding.append(c14n_of(element, algorithm))
    pieces.extend(reversed(preceding))
    for obj in sig.findall("ds:Object", NS):
        if obj.find("xades:QualifyingProperties", NS) is None:
            pieces.append(c14n_of(obj, algorithm))
    return b"".join(pieces)


def _archive_timestamp(
    sig: etree._Element,
    archive: etree._Element,
    octets: Octets,
    spec: SignatureValidationSpec,
    context: Context,
) -> TimestampReport:
    """§5.4 for one archive time-stamp, against the signature as it stands now: a token
    whose imprint no longer matches is TOTAL-FAILED/HASH_FAILURE (PR-TSA-05)."""
    try:
        token, algorithm = _token(archive)
        covered = _archive_octets(sig, archive, octets, _timestamp_c14n(archive))
        imprint = hashlib.new(algorithm, covered).digest()
        return timestamp_report(validate_timestamp(token, imprint, spec, context.timing))
    except Result as result:
        return TimestampReport(result.indication, result.subindication, None, None)
    except _UNREADABLE:
        return TimestampReport(Indication.TOTAL_FAILED, "FORMAT_FAILURE", None, None)


# -- X.509 and the process with time --------------------------------------------------------


@dataclass(frozen=True)
class _Trust:
    subindication: str | None  # ETSI name; None when the certificate validates
    revocation_date: dt.datetime | None
    horizon: dt.datetime | None  # when a TRY_LATER or NO_POE failure starts


def _validate_certificate(
    certificate: asn1_x509.Certificate, spec: SignatureValidationSpec, context: Context
) -> _Trust:
    """§5.2.6, as pyHanko does for CMS (``validate_cert_usage``), with the policy of the
    spec: the trust roots, the key usage (non-repudiation) and the algorithms."""

    async def run() -> Any:
        handlers = bootstrap_validation_data_handlers(spec, timing_info=context.timing)
        validation_context = spec.cert_validation_policy.build_validation_context(
            timing_info=context.timing, handlers=handlers
        )
        return await generic_cms.validate_cert_usage(
            certificate,
            validation_context,
            key_usage_settings=spec.key_usage_settings,
            paths=validation_context.path_builder.async_build_paths_lazy(certificate),
        )

    result = asyncio.run(run())
    subindic = result.error_subindic
    details = result.revo_details
    return _Trust(
        subindication=None if subindic is None else subindic.name,
        revocation_date=None if details is None else details.revocation_date,
        horizon=result.error_time_horizon,
    )


def _with_time(
    trust: _Trust, timestamp: TimestampReport | None, certificate: x509.Certificate
) -> tuple[Indication, str | None]:
    """§5.5.4: a valid signature time-stamp is the proof of existence that can still turn
    some INDETERMINATE results into a pass (the same cases as pyHanko for CAdES)."""
    basic = (
        (Indication.TOTAL_PASSED, None)
        if trust.subindication is None
        else _indication_of(trust.subindication)
    )
    if timestamp is None or trust.subindication not in _FURTHER_WITH_TIME:
        return basic
    if timestamp.indication is not Indication.TOTAL_PASSED or timestamp.time is None:
        return timestamp.indication, timestamp.subindication
    poe = timestamp.time
    sub = trust.subindication
    if sub in ("REVOKED_NO_POE", "REVOKED_CA_NO_POE"):
        if trust.revocation_date is None or poe >= trust.revocation_date:
            return basic
    elif sub == "OUT_OF_BOUNDS_NO_POE":
        if poe < certificate.not_valid_before_utc:
            return Indication.INDETERMINATE, "NOT_YET_VALID"
        if poe > certificate.not_valid_after_utc:
            return basic
    elif sub in ("TRY_LATER", "CRYPTO_CONSTRAINTS_FAILURE_NO_POE") and (
        trust.horizon is None or poe >= trust.horizon
    ):
        return basic
    return Indication.TOTAL_PASSED, None


def _indication_of(subindication: str) -> tuple[Indication, str]:
    """The main indication of an ETSI subindication from the X.509 validation."""
    failures = ("REVOKED", "HASH_FAILURE", "SIG_CRYPTO_FAILURE", "FORMAT_FAILURE")
    if subindication in failures:
        return Indication.TOTAL_FAILED, subindication
    return Indication.INDETERMINATE, subindication


# -- one signature ---------------------------------------------------------------------------


def _packaging(sig: etree._Element, tree: etree._ElementTree) -> XadesPackaging:
    """From what the references point at, not from where the signature sits (a tool may
    wrap enveloping or detached signatures in a container element): its own ``ds:Object``
    is enveloping, a file outside is detached, the document around it is enveloped."""
    uris = [reference.get("URI") for reference in _data_references(sig, tree)]
    for uri in uris:
        if uri is not None and uri.startswith("#") and not uri.startswith("#xpointer("):
            target = unique_by_id(tree, uri[1:])
            if target is not None and _is_object(target, sig):
                return XadesPackaging.ENVELOPING
    if uris and all(uri is None or (uri != "" and not uri.startswith("#")) for uri in uris):
        return XadesPackaging.DETACHED
    return XadesPackaging.ENVELOPED


def _data_references(sig: etree._Element, tree: etree._ElementTree) -> list[etree._Element]:
    """The references to the signed data: not the ``SignedProperties``, not elements of the
    signature itself (``KeyInfo``), except the ``ds:Object`` that holds enveloped content."""
    data = []
    for reference in sig.findall("ds:SignedInfo/ds:Reference", NS):
        uri = reference.get("URI")
        if reference.get("Type") == SIGNED_PROPERTIES:
            continue
        if uri is not None and uri.startswith("#") and not uri.startswith("#xpointer("):
            target = unique_by_id(tree, uri[1:])
            if target is not None and _is_inside(target, sig) and not _is_object(target, sig):
                continue
        data.append(reference)
    return data


def _is_inside(element: etree._Element, sig: etree._Element) -> bool:
    return element is sig or any(ancestor is sig for ancestor in element.iterancestors())


def _is_object(element: etree._Element, sig: etree._Element) -> bool:
    """Whether ``element`` is a ``ds:Object`` of ``sig`` (or inside one) other than the one
    of the ``QualifyingProperties``."""
    for node in (element, *element.iterancestors()):
        if node.tag == DS_OBJECT and node.getparent() is sig:
            return node.find("xades:QualifyingProperties", NS) is None
    return False


def _scope(
    sig: etree._Element, tree: etree._ElementTree, packaging: XadesPackaging, octets: Octets
) -> SignedScope:
    if packaging is XadesPackaging.ENVELOPING:
        return SignedScope.OBJECT
    if packaging is XadesPackaging.DETACHED:
        return SignedScope.EXTERNAL
    root = tree.getroot()
    for reference in _data_references(sig, tree):
        uri = reference.get("URI")
        whole = uri == "" or (
            uri is not None and uri.startswith("#") and unique_by_id(tree, uri[1:]) is root
        )
        if whole and not octets.of(reference)[1]:
            return SignedScope.DOCUMENT
    return SignedScope.PART


def _claimed_time(signed: etree._Element) -> dt.datetime | None:
    element = signed.find("xades:SignedSignatureProperties/xades:SigningTime", NS)
    if element is None or not element.text:
        return None
    try:
        return dt.datetime.fromisoformat(element.text.strip())
    except ValueError:
        return None


def _revocation_values(sig: etree._Element) -> tuple[list[Any], list[Any]]:
    """The OCSP responses and CRLs the signature carries (``RevocationValues``, also those of
    ``TimeStampValidationData``)."""
    ocsps = [
        asn1_ocsp.OCSPResponse.load(base64.b64decode(v.text or ""))
        for v in sig.iterfind(".//xades:EncapsulatedOCSPValue", NS)
    ]
    crls = [
        asn1_crl.CertificateList.load(base64.b64decode(v.text or ""))
        for v in sig.iterfind(".//xades:EncapsulatedCRLValue", NS)
    ]
    return ocsps, crls


def _failed(
    packaging: XadesPackaging,
    result: Result,
    signer: x509.Certificate | None = None,
    claimed: dt.datetime | None = None,
    scope: SignedScope | None = None,
    references: tuple[str, ...] = (),
) -> XadesSignatureReport:
    """A signature that did not pass, with what was read of it before the failure: the
    signer, the declared time and the scope still help the user, as Firma Perú shows them
    on a HASH_FAILURE (real DNIe test of the increment 6)."""
    return XadesSignatureReport(
        packaging=packaging,
        indication=result.indication,
        subindication=result.subindication,
        signer=signer,
        claimed_signing_time=claimed,
        timestamp=None,
        archive_timestamps=(),
        scope=scope,
        references=references,
    )


def _verify_signature(
    sig: etree._Element, tree: etree._ElementTree, external: bytes | None, context: Context
) -> XadesSignatureReport:
    packaging = _packaging(sig, tree)
    # one external file for one external reference: with several, the caller's content
    # cannot be told apart, and each is SIGNED_DATA_NOT_FOUND instead of a false mismatch
    outside = {
        reference.get("URI")
        for reference in sig.findall("ds:SignedInfo/ds:Reference", NS)
        if reference.get("URI") is None or not (reference.get("URI") or "#").startswith("#")
    } - {""}
    octets = Octets(sig, tree, external if len(outside) <= 1 else None)
    signer: x509.Certificate | None = None
    claimed: dt.datetime | None = None
    scope: SignedScope | None = None
    references: tuple[str, ...] = ()
    try:
        signed = _signed_properties(sig, tree)
        carried = _certificates_of(sig)
        signer = _signing_certificate(
            signed, [*carried, *context.store.intermediates, *context.store.roots]
        )
        claimed = _claimed_time(signed)
        references = tuple(r.get("URI") or "" for r in _data_references(sig, tree))
        scope = _scope(sig, tree, packaging, octets)
        weak = check_references(sig, octets) + check_signature_value(sig, signer)
        if weak:
            raise weak_failure("; ".join(weak))
        own_ocsps, own_crls = _revocation_values(sig)
        spec = validation_spec(
            context,
            [*context.store.intermediates, *carried],
            [*own_ocsps, *context.extra_ocsps],
            [*own_crls, *context.extra_crls],
        )
        stamp = sig.find(
            "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/"
            "xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
            NS,
        )
        ts_report = None if stamp is None else _signature_timestamp(sig, stamp, spec, context)
        trust = _validate_certificate(to_asn1(signer), spec, context)
        indicate, subindication = _with_time(trust, ts_report, signer)
        if subindication == GENERIC_CHAIN_FAILURE:
            # the same diagnosis as the PDF and CAdES verifiers (§5.2.6)
            intermediates = [to_asn1(c) for c in carried]
            subindication = diagnose_path(to_asn1(signer), intermediates, spec, context.timing)
        archives = tuple(
            _archive_timestamp(sig, archive, octets, spec, context)
            for archive in sig.iterfind(
                "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/"
                "xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp",
                {**NS, "xades141": XADES141},
            )
        )
    except Result as result:
        return _failed(packaging, result, signer, claimed, scope, references)
    except _UNREADABLE as exc:
        log_malformed(exc)
        return _failed(packaging, format_failure(str(exc)), signer, claimed, scope, references)
    return XadesSignatureReport(
        packaging=packaging,
        indication=indicate,
        subindication=subindication,
        signer=signer,
        claimed_signing_time=claimed,
        timestamp=ts_report,
        archive_timestamps=archives,
        scope=scope,
        references=references,
    )


def _signatures(tree: etree._ElementTree) -> list[etree._Element]:
    """Every ``ds:Signature`` of the document, except countersignatures (they sign another
    signature, not the document, and are not part of this verification)."""
    counter = f"{{{XADES}}}CounterSignature"
    return [
        sig
        for sig in tree.getroot().iter(DS_SIGNATURE)
        if not any(ancestor.tag == counter for ancestor in sig.iterancestors())
    ]


def verify_xades(
    signature: bytes,
    store: TrustStore,
    *,
    content: bytes | None = None,
    moment: dt.datetime | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    timeout: float = 10.0,
) -> XadesVerification:
    """Verify every XAdES signature of the XML document ``signature`` at ``moment`` (now by
    default).

    ``content`` is the file a detached signature (``.xsig``) references; without it, the
    detached signature is INDETERMINATE/SIGNED_DATA_NOT_FOUND. ``ocsp_responses`` and
    ``crls`` (DER) add revocation data to what the signature carries; with ``online`` the
    rest is fetched with the rules of RF-063.

    Raises :class:`~berigna.core.errors.UnreadableDocumentError` when the bytes are not XML
    or declare a DTD (refused like DSS does: entities would change what is digested), and
    :class:`~berigna.core.errors.UnreadableSignatureError` when the document carries no
    ``ds:Signature``.
    """
    when = moment or dt.datetime.now(dt.UTC)
    tree = parse_document(signature)
    if tree.docinfo.doctype:
        raise UnreadableDocumentError("the document declares a DTD (DOCTYPE)")
    signatures = _signatures(tree)
    if not signatures:
        raise UnreadableSignatureError("the XML document carries no ds:Signature")
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
    return XadesVerification(
        signatures=tuple(_verify_signature(sig, tree, content, context) for sig in signatures),
        moment=when,
    )
