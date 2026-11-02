# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""XAdES signatures of XML documents with signxml 4.0.5 (Debian 13) (RF-030 to RF-033, ADR-0008,
SPK-03).

Packaging: enveloped (the signature goes inside the document), enveloping (the document goes
inside ``ds:Object`` of the signature) or detached (the signature is its own XML file, which
references the document by name). Baseline levels (ETSI EN 319 132-1):

- B-B: the signature alone (signxml, ``XAdESSigner``; C14N 1.0 inclusive;
  ``SigningCertificate`` with the signer certificate only).
- B-T: plus ``xades:SignatureTimeStamp`` over ``ds:SignatureValue`` (own code).
- B-LT: plus ``CertificateValues`` and ``RevocationValues`` with the data gathered with the
  signing rules of :func:`berigna.core.validation.signing_validation_context`: the
  certificates of the paths of the signer and of the TSA, without the anchors; the CRLs and
  the OCSP responses, each once (own code; with the DNIe, OCSP, SPK-02).
- B-LTA: plus ``xades141:ArchiveTimeStamp`` over the data objects, ``SignedInfo``,
  ``SignatureValue``, ``KeyInfo``, the unsigned properties and the other ``ds:Object``
  elements (EN 319 132-1 §5.4.2; SPK-03 §4: it covers every ``ds:Object`` except the one of
  ``QualifyingProperties``, also the referenced ones).

As in CAdES, the levels above B-T are added after the card has signed: if a service fails,
the signature is kept and the result carries the level reached and the reason.
"""

import asyncio
import base64
import copy
import enum
import hashlib
import io
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, cast

from asn1crypto import cms
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from lxml import etree
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.sign.timestamps.common_utils import TimestampRequestError
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from signxml import methods
from signxml.xades.xades import XAdESSigner

from berigna.core.certs import to_asn1
from berigna.core.errors import (
    AlreadySignedError,
    TsaError,
    UnreadableDocumentError,
    XmlDtdError,
    XmlFormatError,
    XmlPrologueError,
)
from berigna.core.formats.cades import signer_certificate
from berigna.core.formats.common import (
    VALIDATION_SERVICE_ERRORS,
    SignatureLevel,
    required,
)
from berigna.core.token.base import HashAlgorithmName, TokenSigner

DS = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"
XADES141 = "http://uri.etsi.org/01903/v1.4.1#"
# References without Transforms are canonicalised with C14N 1.0 (XMLDSig); using it for
# SignedInfo too keeps signxml and the validators (DSS/Santuario) in agreement (SPK-03 §3).
C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED = f"{DS}enveloped-signature"
NS = {"ds": DS, "xades": XADES}
_DIGESTS = {hashes.SHA256: "sha256", hashes.SHA384: "sha384", hashes.SHA512: "sha512"}
# The Id of an element of the signature document, as a variable: never interpolating the
# value into the expression (review of 2026-11-01).
_BY_ID = etree.XPath("//*[@Id=$id]")

# The archive time-stamp of B-LTA may fail on the TSA or on the data: the B-LT is kept.
_ARCHIVE_ERRORS: tuple[type[Exception], ...] = (TimestampRequestError, *VALIDATION_SERVICE_ERRORS)


class XadesPackaging(enum.Enum):
    """RF-030 to RF-032. The names of the outputs are those of
    :func:`berigna.core.signing.xades_output_path`; detached writes ``.xsig``."""

    ENVELOPED = "enveloped"
    ENVELOPING = "enveloping"
    DETACHED = "detached"


@dataclass(frozen=True)
class XadesResult:
    data: bytes  # the signed XML document, with an XML declaration; enveloped keeps the
    # encoding of the original
    level: SignatureLevel  # level reached; lower than requested only if ``note`` says why
    note: str | None = None


class _TokenKey:
    """Duck-typed RSA key for signxml (SPK-03 §2): hashes locally, signs the digest in the token,
    so the private key never leaves the device (RNF-SEG-01)."""

    def __init__(self, token: TokenSigner, public_key: Any, digest: HashAlgorithmName) -> None:
        self._token = token
        self._public = public_key
        self._digest = digest

    def sign(self, data: bytes, padding: Any, algorithm: Any) -> bytes:
        name = _DIGESTS.get(type(algorithm))
        if name is None or name != self._digest:
            raise ValueError(f"unexpected digest algorithm {algorithm!r}")
        if not isinstance(padding, asym_padding.PKCS1v15):  # the only one XMLDSig RSA allows
            raise ValueError(f"unexpected padding {padding!r}")
        return self._token.sign_digest(
            hashlib.new(name, data).digest(), cast(HashAlgorithmName, name)
        )

    def public_key(self) -> Any:
        return self._public


def _signer(packaging: XadesPackaging, digest: HashAlgorithmName) -> XAdESSigner:
    method = {
        XadesPackaging.ENVELOPED: methods.enveloped,
        XadesPackaging.ENVELOPING: methods.enveloping,
        XadesPackaging.DETACHED: methods.detached,
    }[packaging]
    return XAdESSigner(
        method=method,
        signature_algorithm=f"rsa-{digest}",
        digest_algorithm=digest,
        c14n_algorithm=C14N10,
    )


def _parse_document(content: bytes | str) -> etree._ElementTree:
    """The whole document (prologue included), with a hardened parser: no entity resolution,
    no network, no DTD loading (review of 2026-11-01). Raises
    :class:`~berigna.core.errors.UnreadableDocumentError` when ``content`` is not XML."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    data = content.encode() if isinstance(content, str) else content
    try:
        return etree.parse(io.BytesIO(data), parser)
    except etree.XMLSyntaxError as exc:
        raise UnreadableDocumentError(f"cannot read this XML document: {exc}") from exc


def parse_xml(content: bytes | str) -> etree._Element:
    """The root element of the document to sign, or
    :class:`~berigna.core.errors.UnreadableDocumentError`. See :func:`_parse_document`."""
    return _parse_document(content).getroot()


def _has_instructions_outside(root: etree._Element) -> bool:
    """Whether the prologue or the epilogue of the document carries processing instructions.
    Comments outside the root are harmless — C14N without comments excludes them on both
    sides — but a validator digests the instructions (DSS 6.2, review of 2026-11-01), and
    the reference digests of the enveloped and detached forms cover the root element alone."""
    node = root.getprevious()
    while node is not None:
        if isinstance(node, etree._ProcessingInstruction):
            return True
        node = node.getprevious()
    node = root.getnext()
    while node is not None:
        if isinstance(node, etree._ProcessingInstruction):
            return True
        node = node.getnext()
    return False


def check_xml_signable(content: bytes, packaging: XadesPackaging) -> None:
    """Raise, before the PIN is requested, when ``content`` cannot be signed in ``packaging``:
    :class:`~berigna.core.errors.XmlFormatError` if it is not XML or damaged,
    :class:`~berigna.core.errors.XmlDtdError` if it declares a DTD,
    :class:`~berigna.core.errors.XmlPrologueError` if it carries processing instructions
    outside the root and the form digests the document (detached, or enveloped without an Id
    on the root to point the reference at), and :class:`~berigna.core.errors.AlreadySignedError`
    if it already carries a ``ds:Signature`` and an enveloped signature would break it (review
    of 2026-11-01).

    As :func:`berigna.core.formats.pades.check_pdf_signable`: called before the PIN, so none
    of these costs the user a PIN entry.
    """
    try:
        tree = _parse_document(content)
    except UnreadableDocumentError as exc:
        raise XmlFormatError(f"cannot read this XML document: {exc}") from exc
    if tree.docinfo.doctype:
        raise XmlDtdError("the document declares a DTD (DOCTYPE)")
    root = tree.getroot()
    enveloped = packaging is XadesPackaging.ENVELOPED
    # the detached reference names the file, and an enveloped one without an Id on the root
    # uses URI="": both digest the document, instructions included, on the validator's side
    references_the_document = packaging is XadesPackaging.DETACHED or (
        enveloped and root.get("Id") is None and root.get("ID") is None
    )
    if _has_instructions_outside(root) and references_the_document:
        raise XmlPrologueError(
            "processing instructions outside the root are outside the reference digest"
        )
    if enveloped and (
        root.tag == f"{{{DS}}}Signature" or root.find(".//ds:Signature", NS) is not None
    ):
        raise AlreadySignedError("an enveloped signature would break the signature it already has")


def signature_element(document: etree._Element) -> etree._Element:
    """The ``ds:Signature`` of ``document``, whichever packaging produced it, or ValueError
    when there is none."""
    if document.tag == f"{{{DS}}}Signature":
        return document
    signature = document.find(".//ds:Signature", NS)
    if signature is None:
        raise ValueError("the document carries no ds:Signature")
    return signature


def _unsigned_properties(sig: etree._Element) -> etree._Element:
    qualifying = sig.find(".//xades:QualifyingProperties", NS)
    if qualifying is None:
        raise ValueError("the signature has no QualifyingProperties")
    unsigned = qualifying.find("xades:UnsignedProperties", NS)
    if unsigned is None:
        unsigned = etree.SubElement(qualifying, f"{{{XADES}}}UnsignedProperties")
    properties = unsigned.find("xades:UnsignedSignatureProperties", NS)
    if properties is None:
        properties = etree.SubElement(unsigned, f"{{{XADES}}}UnsignedSignatureProperties")
    return properties


def _token_certificates(token_content: cms.SignedData) -> list[asn1_x509.Certificate]:
    choices = token_content["certificates"]
    if not choices.native:
        return []
    return [choice.chosen for choice in choices if choice.name == "certificate"]


async def _add_signature_timestamp(
    sig: etree._Element, stamper: TimeStamper, digest: HashAlgorithmName
) -> bytes:
    """B-T: ``SignatureTimeStamp`` over the exclusive C14N of ``ds:SignatureValue``
    (EN 319 132-1 §5.4.1). Returns the DER of the time-stamp token, for B-LT."""
    value = sig.find("ds:SignatureValue", NS)
    imprint = hashlib.new(
        digest, etree.tostring(value, method="c14n", exclusive=True, with_comments=False)
    ).digest()
    token = await stamper.async_timestamp(imprint, digest)
    der = bytes(token.dump())
    time_stamp = etree.SubElement(_unsigned_properties(sig), f"{{{XADES}}}SignatureTimeStamp")
    etree.SubElement(time_stamp, f"{{{DS}}}CanonicalizationMethod", Algorithm=EXC_C14N)
    etree.SubElement(time_stamp, f"{{{XADES}}}EncapsulatedTimeStamp").text = base64.b64encode(
        der
    ).decode()
    return der


async def _add_validation_data(
    sig: etree._Element,
    chain: Sequence[x509.Certificate],
    timestamp: bytes,
    context: ValidationContext,
) -> None:
    """B-LT: validate the paths of the signer and of the TSA with ``context`` and add
    ``CertificateValues`` and ``RevocationValues`` with the certificates (not the anchors)
    and the revocation data that it gathered, each once."""
    signer = to_asn1(chain[-1])
    certificates = [signer]
    known = {signer.dump()}
    token_content = cms.ContentInfo.load(timestamp)["content"]
    tsa_certs = _token_certificates(token_content)  # may be empty
    # signer_certificate raises ValueError when the TSA did not embed it: a service failure,
    # the level lowers with the reason
    tsa = signer_certificate(token_content)
    intermediates = [to_asn1(c) for c in chain[:-1]] + tsa_certs
    for leaf in (signer, tsa):
        validator = CertificateValidator(
            leaf, intermediate_certs=intermediates, validation_context=context
        )
        path = await validator.async_validate_path()
        for member in path.iter_certs(include_root=False):
            if member.dump() not in known:
                known.add(member.dump())
                certificates.append(member)
    values = etree.SubElement(_unsigned_properties(sig), f"{{{XADES}}}CertificateValues")
    for certificate in certificates:
        etree.SubElement(values, f"{{{XADES}}}EncapsulatedX509Certificate").text = base64.b64encode(
            certificate.dump()
        ).decode()
    revocation = etree.SubElement(_unsigned_properties(sig), f"{{{XADES}}}RevocationValues")
    crls = list({crl.dump(): crl for crl in context.crls}.values())
    if crls:
        crl_values = etree.SubElement(revocation, f"{{{XADES}}}CRLValues")
        for crl in crls:
            etree.SubElement(
                crl_values, f"{{{XADES}}}EncapsulatedCRLValue"
            ).text = base64.b64encode(crl.dump()).decode()
    responses = list({response.dump(): response for response in context.ocsps}.values())
    if responses:
        ocsp_values = etree.SubElement(revocation, f"{{{XADES}}}OCSPValues")
        for response in responses:
            etree.SubElement(
                ocsp_values, f"{{{XADES}}}EncapsulatedOCSPValue"
            ).text = base64.b64encode(response.dump()).decode()


def _without_signature(element: etree._Element, sig: etree._Element) -> etree._Element:
    """A copy of ``element`` without ``sig`` — only that one: the enveloped transform excises
    the signature the reference belongs to, not the ones the document already carried."""
    without = copy.deepcopy(element)
    copies = without.findall(".//ds:Signature", NS)
    own = copies[element.findall(".//ds:Signature", NS).index(sig)]
    own.getparent().remove(own)
    return without


def _reference_octets(
    document: etree._Element, sig: etree._Element, reference: etree._Element, data: etree._Element
) -> bytes:
    """The octets of one ``ds:Reference`` as used for the archive time-stamp (EN 319 132-1
    §5.4.2 / SPK-03 §4): the data objects, with the reference's transforms applied — the
    enveloped one removes only the signature it belongs to — and the elements of the
    signature document as node-sets (archive c14n, C14N 1.0).

    C14N without comments, as XMLDSig does for ``URI=""`` and ``#id`` and as the declared
    CanonicalizationMethod says: lxml includes the comments unless ``with_comments=False``
    (review of 2026-11-01)."""
    uri = reference.get("URI")
    transforms = [t.get("Algorithm") for t in reference.findall("ds:Transforms/ds:Transform", NS)]
    exclusive = EXC_C14N in transforms
    if uri == "":  # the whole document, without this signature (enveloped transform)
        target = _without_signature(document, sig)
    elif uri.startswith("#"):  # an element of the signature document
        [target] = _BY_ID(sig.getroottree().getroot(), id=uri[1:])
        if ENVELOPED in transforms and sig in target.findall(".//ds:Signature", NS):
            target = _without_signature(target, sig)  # the enveloped transform on #id
    else:
        target = data  # the external document, as the DigestValue was computed over it
        exclusive = False
    return bytes(etree.tostring(target, method="c14n", exclusive=exclusive, with_comments=False))


async def _add_archive_timestamp(
    document: etree._Element,
    sig: etree._Element,
    data: etree._Element,
    stamper: TimeStamper,
    digest: HashAlgorithmName,
) -> None:
    """B-LTA: ``xades141:ArchiveTimeStamp`` over the data objects, ``SignedInfo``,
    ``SignatureValue``, ``KeyInfo``, the unsigned properties it finds and the other
    ``ds:Object`` elements (EN 319 132-1 §5.4.2; every ``ds:Object`` except the one of
    ``QualifyingProperties``, also the referenced ones, SPK-03 §4)."""
    h = hashlib.new(digest, b"")
    for reference in sig.findall("ds:SignedInfo/ds:Reference", NS):
        h.update(_reference_octets(document, sig, reference, data))
    for path in ("ds:SignedInfo", "ds:SignatureValue", "ds:KeyInfo"):
        element = sig.find(path, NS)
        if element is not None:
            h.update(
                bytes(etree.tostring(element, method="c14n", exclusive=False, with_comments=False))
            )
    properties = _unsigned_properties(sig)
    for element in properties:  # the archive time-stamp is added after, not hashed
        h.update(
            bytes(etree.tostring(element, method="c14n", exclusive=False, with_comments=False))
        )
    for obj in sig.findall("ds:Object", NS):
        if obj.find("xades:QualifyingProperties", NS) is None:
            h.update(
                bytes(etree.tostring(obj, method="c14n", exclusive=False, with_comments=False))
            )
    token = await stamper.async_timestamp(h.digest(), digest)
    archive = etree.SubElement(
        properties, f"{{{XADES141}}}ArchiveTimeStamp", nsmap={"xades141": XADES141}
    )
    etree.SubElement(archive, f"{{{DS}}}CanonicalizationMethod", Algorithm=C14N10)
    etree.SubElement(archive, f"{{{XADES}}}EncapsulatedTimeStamp").text = base64.b64encode(
        bytes(token.dump())
    ).decode()


def _serialize(document: etree._Element, tree: etree._ElementTree) -> bytes:
    """The signed document, always with an XML declaration. The enveloped form is the
    original document plus the signature: its prologue (processing instructions, comments
    outside the root) and its encoding are kept, instead of a rewritten UTF-8 root (review
    of 2026-11-01); the enveloping and detached forms are the signature document, UTF-8."""
    if document.tag != f"{{{DS}}}Signature":  # enveloped: the document the user gave
        return bytes(
            etree.tostring(
                document.getroottree(),
                xml_declaration=True,
                encoding=tree.docinfo.encoding or "UTF-8",
            )
        )
    return bytes(etree.tostring(document, xml_declaration=True, encoding="UTF-8"))


def sign_xades(
    content: bytes,
    token: TokenSigner,
    chain: Sequence[x509.Certificate],
    *,
    packaging: XadesPackaging = XadesPackaging.ENVELOPED,
    level: SignatureLevel = SignatureLevel.B_B,
    digest: HashAlgorithmName = "sha256",
    reference_uri: str | None = None,
    timestamper: TimeStamper | None = None,
    validation_context: ValidationContext | None = None,
) -> XadesResult:
    """Return a XAdES signature of the XML ``content`` at ``level``.

    ``chain`` goes from the trust anchor to the signer certificate (as returned by
    :func:`berigna.core.validation.check_signer`); the anchor is not embedded. B-T and above
    need ``timestamper``; B-LT and B-LTA also ``validation_context``. Detached needs
    ``reference_uri``, the name under which the document travels with the signature. A TSA
    failure while time-stamping the signature raises :class:`~berigna.core.errors.TsaError`;
    a document that is not XML raises :class:`~berigna.core.errors.XmlFormatError`, one with
    a DTD :class:`~berigna.core.errors.XmlDtdError`, one with processing instructions outside
    the root in a form that digests the document
    :class:`~berigna.core.errors.XmlPrologueError`, and an already-signed one in the
    enveloped form :class:`~berigna.core.errors.AlreadySignedError`, all before the card
    signs.
    """
    check_xml_signable(content, packaging)
    stamper = (
        required(timestamper, level, "a time-stamper") if level is not SignatureLevel.B_B else None
    )
    long_term = level in (SignatureLevel.B_LT, SignatureLevel.B_LTA)
    context = required(validation_context, level, "a validation context") if long_term else None
    if packaging is XadesPackaging.DETACHED and reference_uri is None:
        raise ValueError("a detached XAdES signature needs the URI of the document")
    return asyncio.run(
        _sign(content, token, chain, packaging, level, digest, reference_uri, stamper, context)
    )


async def _sign(
    content: bytes,
    token: TokenSigner,
    chain: Sequence[x509.Certificate],
    packaging: XadesPackaging,
    level: SignatureLevel,
    digest: HashAlgorithmName,
    reference_uri: str | None,
    stamper: TimeStamper | None,
    context: ValidationContext | None,
) -> XadesResult:
    """All the steps in one event loop, so that the services share it."""
    tree = _parse_document(content)
    data = tree.getroot()
    signer = _signer(packaging, digest)
    key = _TokenKey(token, chain[-1].public_key(), digest)
    signed = signer.sign(  # type: ignore[call-arg]  # @wraps confuses mypy (signxml 4.0.5)
        # the whole tree, so that the enveloped output keeps the prologue of the original
        data=tree,
        key=key,
        cert=[chain[-1]],
        reference_uri=reference_uri if packaging is XadesPackaging.DETACHED else None,
    )
    document = signed
    sig = signature_element(signed)
    try:
        timestamp = (
            await _add_signature_timestamp(sig, stamper, digest) if stamper is not None else None
        )
    except TimestampRequestError as exc:
        raise TsaError(f"the TSA did not time-stamp the signature: {exc}") from exc
    if timestamp is None:
        return XadesResult(_serialize(document, tree), SignatureLevel.B_B)
    if context is None:
        return XadesResult(_serialize(document, tree), SignatureLevel.B_T)
    try:
        await _add_validation_data(sig, chain, timestamp, context)
    except VALIDATION_SERVICE_ERRORS as exc:
        note = f"validation data not embedded: {exc}"
        return XadesResult(_serialize(document, tree), SignatureLevel.B_T, note)
    if level is SignatureLevel.B_LT:
        return XadesResult(_serialize(document, tree), SignatureLevel.B_LT)
    try:
        await _add_archive_timestamp(document, sig, data, cast(TimeStamper, stamper), digest)
    except _ARCHIVE_ERRORS as exc:
        note = f"archive time-stamp not added: {exc}"
        return XadesResult(_serialize(document, tree), SignatureLevel.B_LT, note)
    return XadesResult(_serialize(document, tree), SignatureLevel.B_LTA)
