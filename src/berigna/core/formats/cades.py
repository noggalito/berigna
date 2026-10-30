# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""CAdES signatures of any file with pyHanko 0.25.x (RF-020 to RF-022, ADR-0008, SPK-03).

Packaging: detached (``.p7s``, next to the file, which is not touched) or enveloping
(``.p7m``, which contains the file). Baseline levels (ETSI EN 319 122-1):

- B-B: the signature alone (pyHanko, ``use_cades``).
- B-T: plus a signature time-stamp (pyHanko).
- B-LT: plus the validation data of the signer and of the TSA, gathered with the signing rules
  of :func:`berigna.core.validation.signing_validation_context`: the certificates of their
  paths in ``SignedData.certificates``; the CRLs, and the OCSP responses as
  ``id-ri-ocsp-response`` (RFC 5940), in ``SignedData.crls``. Own code.
- B-LTA: plus an ``archive-time-stamp-v3`` with its ``ats-hash-index-v3`` (EN 319 122-1
  §5.5.3). Own code, as validated against DSS 6.2 in SPK-03.

As in PAdES, the levels above B-T are added after the card has signed: if a service fails,
the signature is kept and the result carries the level reached and the reason.
"""

import asyncio
import enum
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from asn1crypto import algos, cms, core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.sign.timestamps.common_utils import TimestampRequestError
from pyhanko_certvalidator import CertificateValidator, ValidationContext

from berigna.core.certs import to_asn1
from berigna.core.errors import TsaError
from berigna.core.formats.common import (
    VALIDATION_SERVICE_ERRORS,
    SignatureLevel,
    TokenCmsSigner,
    required,
)
from berigna.core.token.base import HashAlgorithmName, TokenSigner

OID_ATS_HASH_INDEX_V3 = "0.4.0.19122.1.5"
OID_ARCHIVE_TIME_STAMP_V3 = "0.4.0.1733.2.4"

# The archive time-stamp of B-LTA may fail on the TSA or on the data: the B-LT is kept.
_ARCHIVE_ERRORS: tuple[type[Exception], ...] = (TimestampRequestError, *VALIDATION_SERVICE_ERRORS)


class CadesPackaging(enum.Enum):
    """RF-020 and RF-021; the value is the file extension."""

    DETACHED = "p7s"
    ENVELOPING = "p7m"


@dataclass(frozen=True)
class CadesResult:
    data: bytes  # DER of the CMS ContentInfo
    level: SignatureLevel  # level reached; lower than requested only if ``note`` says why
    note: str | None = None


class _OctetStrings(core.SequenceOf):  # type: ignore[misc]
    _child_spec = core.OctetString


class AtsHashIndexV3(core.Sequence):  # type: ignore[misc]
    """``ats-hash-index-v3`` (EN 319 122-1 §5.5.2)."""

    _fields: ClassVar = [
        # Encoded explicitly, not left as the DER default: DSS and BouncyCastle rebuild the
        # index with the algorithm present, and the time-stamp imprint covers it (SPK-03).
        ("hash_ind_algorithm", algos.DigestAlgorithm),
        ("certificates_hash_index", _OctetStrings),
        ("crls_hash_index", _OctetStrings),
        ("unsigned_attr_values_hash_index", _OctetStrings),
    ]


def sign_cades(
    content: bytes,
    token: TokenSigner,
    chain: Sequence[x509.Certificate],
    *,
    packaging: CadesPackaging = CadesPackaging.DETACHED,
    level: SignatureLevel = SignatureLevel.B_B,
    digest: HashAlgorithmName = "sha256",
    timestamper: TimeStamper | None = None,
    validation_context: ValidationContext | None = None,
) -> CadesResult:
    """Return a CAdES signature of ``content`` at ``level``.

    ``chain`` goes from the trust anchor to the signer certificate (as returned by
    :func:`berigna.core.validation.check_signer`); the anchor is not embedded. B-T and above
    need ``timestamper``; B-LT and B-LTA also ``validation_context``. A TSA failure while
    time-stamping the signature raises :class:`~berigna.core.errors.TsaError`.
    """
    stamper = (
        required(timestamper, level, "a time-stamper") if level is not SignatureLevel.B_B else None
    )
    long_term = level in (SignatureLevel.B_LT, SignatureLevel.B_LTA)
    context = required(validation_context, level, "a validation context") if long_term else None

    return asyncio.run(_sign(content, token, chain, packaging, level, digest, stamper, context))


async def _sign(
    content: bytes,
    token: TokenSigner,
    chain: Sequence[x509.Certificate],
    packaging: CadesPackaging,
    level: SignatureLevel,
    digest: HashAlgorithmName,
    stamper: TimeStamper | None,
    context: ValidationContext | None,
) -> CadesResult:
    """All the steps in one event loop, so that the services share it."""
    signer = TokenCmsSigner(token, chain, digest)
    try:
        signed: cms.ContentInfo = await signer.async_sign_general_data(
            content,
            digest,
            detached=packaging is CadesPackaging.DETACHED,
            use_cades=True,
            timestamper=stamper,
        )
    except TimestampRequestError as exc:
        raise TsaError(f"the TSA did not time-stamp the signature: {exc}") from exc
    if stamper is None:
        return CadesResult(signed.dump(), SignatureLevel.B_B)
    if context is None:
        return CadesResult(signed.dump(), SignatureLevel.B_T)
    try:
        signed = await _add_validation_data(signed, to_asn1(chain[-1]), context)
    except VALIDATION_SERVICE_ERRORS as exc:
        note = f"validation data not embedded: {exc}"
        return CadesResult(signed.dump(), SignatureLevel.B_T, note)
    if level is SignatureLevel.B_LT:
        return CadesResult(signed.dump(), SignatureLevel.B_LT)
    try:
        signed = await _add_archive_timestamp(signed, stamper, digest)
    except _ARCHIVE_ERRORS as exc:
        note = f"archive time-stamp not added: {exc}"
        return CadesResult(signed.dump(), SignatureLevel.B_LT, note)
    return CadesResult(signed.dump(), SignatureLevel.B_LTA)


def _certificates(signed_data: cms.SignedData) -> list[asn1_x509.Certificate]:
    if not signed_data["certificates"].native:
        return []
    return [choice.chosen for choice in signed_data["certificates"] if choice.name == "certificate"]


def signer_certificate(signed_data: cms.SignedData) -> asn1_x509.Certificate:
    """The certificate that ``sid`` of the first SignerInfo names, among the embedded ones."""
    sid = signed_data["signer_infos"][0]["sid"]
    for certificate in _certificates(signed_data):
        if sid.name == "issuer_and_serial_number":
            if (
                certificate.issuer == sid.chosen["issuer"]
                and certificate.serial_number == sid.chosen["serial_number"].native
            ):
                return certificate
        # The extension, or method 1 of RFC 5280 §4.2.1.2 for a certificate without it.
        elif sid.chosen.native in (certificate.key_identifier, certificate.public_key.sha1):
            return certificate
    raise ValueError("the signer certificate is not embedded")


def _revocation(signed_data: cms.SignedData) -> list[cms.RevocationInfoChoice]:
    crls = signed_data["crls"]
    return [] if isinstance(crls, core.Void) else list(crls)


def _unsigned(signer_info: cms.SignerInfo) -> list[cms.CMSAttribute]:
    # Not ``.native``: asn1crypto cannot render the archive time-stamp attribute it does not know.
    attributes = signer_info["unsigned_attrs"]
    return [] if isinstance(attributes, core.Void) else list(attributes)


def signature_timestamp(signer_info: cms.SignerInfo) -> cms.SignedData | None:
    """The token of the ``signature-time-stamp`` attribute (B-T), if the signature has one."""
    for attribute in _unsigned(signer_info):
        if attribute["type"].native == "signature_time_stamp_token":
            token: cms.SignedData = attribute["values"][0]["content"]
            return token
    return None


async def _add_validation_data(
    signed: cms.ContentInfo, leaf: asn1_x509.Certificate, context: ValidationContext
) -> cms.ContentInfo:
    """B-LT: validate the paths of the signer and of the TSA with ``context`` and embed the
    certificates (not the anchors) and the revocation data that it gathered."""
    signed_data = signed["content"]
    own = _certificates(signed_data)
    embedded = list(own)
    to_validate = [leaf]
    timestamp = signature_timestamp(signed_data["signer_infos"][0])
    if timestamp is not None:
        embedded += _certificates(timestamp)
        to_validate.append(signer_certificate(timestamp))
    known = {certificate.dump() for certificate in own}
    certificates = [cms.CertificateChoices(name="certificate", value=c) for c in own]
    for certificate in to_validate:
        validator = CertificateValidator(
            certificate, intermediate_certs=embedded, validation_context=context
        )
        path = await validator.async_validate_path()
        for member in path.iter_certs(include_root=False):
            if member.dump() not in known:
                known.add(member.dump())
                certificates.append(cms.CertificateChoices(name="certificate", value=member))
    # Supplied and fetched data may repeat: each item once.
    crls = list({crl.dump(): crl for crl in context.crls}.values())
    responses = list({response.dump(): response for response in context.ocsps}.values())
    revocation = [cms.RevocationInfoChoice(name="crl", value=crl) for crl in crls]
    revocation += [
        cms.RevocationInfoChoice(
            name="other",
            value={"other_rev_info_format": "ocsp_response", "other_rev_info": response},
        )
        for response in responses
    ]
    signed_data["certificates"] = cms.CertificateSet(certificates)
    if revocation:  # an empty [1] SET is not written
        signed_data["crls"] = cms.RevocationInfoChoices(revocation)
    if responses:
        signed_data["version"] = "v5"  # RFC 5652 §5.1: "other" revocation information
    return cms.ContentInfo.load(signed.dump(force=True))


async def _add_archive_timestamp(
    signed: cms.ContentInfo, stamper: TimeStamper, digest: HashAlgorithmName
) -> cms.ContentInfo:
    """B-LTA: ``archive-time-stamp-v3`` over the content, the SignerInfo and the hash index of
    the certificates, revocation data and unsigned attributes (EN 319 122-1 §5.5.3)."""
    signed_data = signed["content"]
    signer_info = signed_data["signer_infos"][0]
    unsigned = _unsigned(signer_info)

    def h(data: bytes) -> bytes:
        return hashlib.new(digest, data).digest()

    index = AtsHashIndexV3(
        {
            "hash_ind_algorithm": {"algorithm": digest},
            "certificates_hash_index": [h(c.dump()) for c in signed_data["certificates"]],
            "crls_hash_index": [h(c.dump()) for c in _revocation(signed_data)],
            "unsigned_attr_values_hash_index": [
                h(a["type"].dump() + v.dump()) for a in unsigned for v in a["values"]
            ],
        }
    )
    fields = b"".join(
        signer_info[name].dump()
        for name in (
            "version",
            "sid",
            "digest_algorithm",
            "signed_attrs",
            "signature_algorithm",
            "signature",
        )
    )
    # H(content) is the message-digest signed attribute: the content is not hashed again.
    content_digest = next(
        a["values"][0].native
        for a in signer_info["signed_attrs"]
        if a["type"].native == "message_digest"
    )
    imprint = (
        signed_data["encap_content_info"]["content_type"].dump()
        + content_digest
        + fields
        + index.dump()
    )
    token: cms.ContentInfo = await stamper.async_timestamp(h(imprint), digest)
    token_info = token["content"]["signer_infos"][0]
    token_info["unsigned_attrs"] = cms.CMSAttributes(
        [
            *_unsigned(token_info),
            cms.CMSAttribute({"type": OID_ATS_HASH_INDEX_V3, "values": [index]}),
        ]
    )
    token = cms.ContentInfo.load(token.dump(force=True))
    archive = cms.CMSAttribute({"type": OID_ARCHIVE_TIME_STAMP_V3, "values": [token]})
    signer_info["unsigned_attrs"] = cms.CMSAttributes([*unsigned, archive])
    return cms.ContentInfo.load(signed.dump(force=True))
