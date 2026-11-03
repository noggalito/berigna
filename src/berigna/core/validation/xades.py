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
3. Cryptographic verification (§5.2.7): every reference is dereferenced and transformed here,
   with an allow-list of transforms (enveloped signature, XPath Filter 2.0 ``subtract``,
   base64, the canonicalizations), and digested; then ``SignatureValue`` over the canonicalized
   ``SignedInfo``. A difference is TOTAL-FAILED/HASH_FAILURE or SIG_CRYPTO_FAILURE; SHA-1,
   MD5 and RSA under 2048 bits are INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE (ACR-18).
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
import copy
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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
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
from berigna.core.formats.xades import DS, NS, XADES, XADES141, XadesPackaging, parse_document
from berigna.core.trust import TrustStore
from berigna.core.validation.algorithms import MIN_RSA_BITS, WEAK_DIGESTS
from berigna.core.validation.preflight import time_tolerance
from berigna.core.validation.spec import (
    GENERIC_CHAIN_FAILURE,
    MALFORMED,
    Context,
    Indication,
    TimestampReport,
    diagnose_path,
    timestamp_report,
    validate_timestamp,
    validation_spec,
)

__all__ = [
    "SignedScope",
    "XadesSignatureReport",
    "XadesVerification",
    "verify_xades",
]

_MORE = "http://www.w3.org/2001/04/xmldsig-more#"
_XMLENC = "http://www.w3.org/2001/04/xmlenc#"
_DIGEST_METHODS = {
    f"{DS}sha1": "sha1",
    f"{_MORE}md5": "md5",
    f"{_MORE}sha224": "sha224",
    f"{_XMLENC}sha256": "sha256",
    f"{_MORE}sha384": "sha384",
    f"{_XMLENC}sha512": "sha512",
}
_SIGNATURE_METHODS = {
    f"{DS}rsa-sha1": ("rsa", "sha1"),
    f"{_MORE}rsa-md5": ("rsa", "md5"),
    f"{_MORE}rsa-sha224": ("rsa", "sha224"),
    f"{_MORE}rsa-sha256": ("rsa", "sha256"),
    f"{_MORE}rsa-sha384": ("rsa", "sha384"),
    f"{_MORE}rsa-sha512": ("rsa", "sha512"),
    f"{_MORE}ecdsa-sha1": ("ecdsa", "sha1"),
    f"{_MORE}ecdsa-sha224": ("ecdsa", "sha224"),
    f"{_MORE}ecdsa-sha256": ("ecdsa", "sha256"),
    f"{_MORE}ecdsa-sha384": ("ecdsa", "sha384"),
    f"{_MORE}ecdsa-sha512": ("ecdsa", "sha512"),
}
_HASHES: dict[str, type[hashes.HashAlgorithm]] = {
    "sha1": hashes.SHA1,
    "md5": hashes.MD5,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
_C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
# algorithm -> (exclusive, with comments)
_CANONICALIZATIONS = {
    _C14N10: (False, False),
    f"{_C14N10}#WithComments": (False, True),
    _C14N11: (False, False),
    f"{_C14N11}#WithComments": (False, True),
    _EXC_C14N: (True, False),
    f"{_EXC_C14N}WithComments": (True, True),
}
_ENVELOPED = f"{DS}enveloped-signature"
_FILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2"
_BASE64 = f"{DS}base64"
_SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties"
_XML_NS = "http://www.w3.org/XML/1998/namespace"
_SIGNATURE = f"{{{DS}}}Signature"
_OBJECT = f"{{{DS}}}Object"
# Id, ID and id: the names that DSS (Santuario) registers as identifiers too. An identifier
# that two elements share is refused (AM-06), whatever its spelling.
_BY_ID = etree.XPath("//*[@Id=$id or @ID=$id or @id=$id]")
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
# What a hostile signature raises past the parser: also cryptography's InvalidVersion (a
# certificate with a mutated version) and pyHanko's AttributeError (a time-stamp token whose
# digest OID it does not know; ``get_pyca_cryptography_hash`` looks it up with getattr).
_UNREADABLE = (
    *MALFORMED,
    binascii.Error,
    etree.LxmlError,
    IndexError,
    x509.InvalidVersion,
    AttributeError,
)


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


class _Result(Exception):
    """An ETSI result reached before the end of the process (a failed step)."""

    def __init__(self, indicate: Indication, subindication: str, reason: str) -> None:
        super().__init__(reason)
        self.indication = indicate
        self.subindication = subindication


def _format(reason: str) -> _Result:
    return _Result(Indication.TOTAL_FAILED, "FORMAT_FAILURE", reason)


def _weak(reason: str) -> _Result:
    return _Result(Indication.INDETERMINATE, "CRYPTO_CONSTRAINTS_FAILURE", reason)


# -- references (XMLDSig §4.4.3, with an allow-list of transforms) --------------------------


@dataclass
class _NodeSet:
    """A same-document node-set: a private copy of the document and the element at the apex
    (``None`` for the whole document), from which transforms remove subtrees."""

    tree: etree._ElementTree
    apex: etree._Element | None
    excludes_content: bool = False  # something other than a signature was removed


def _copy_of(tree: etree._ElementTree, element: etree._Element) -> tuple[Any, etree._Element]:
    """A copy of ``tree`` and the element in it that corresponds to ``element``."""
    clone = copy.deepcopy(tree)
    return clone, _same_in(clone, tree, element)


def _same_in(clone: etree._ElementTree, tree: etree._ElementTree, element: etree._Element) -> Any:
    """The element of ``clone`` (a copy of ``tree``) at the place of ``element``."""
    if element is tree.getroot():
        return clone.getroot()
    same = clone.find(tree.getelementpath(element))  # "{uri}name[n]" steps from the root
    if same is None:  # pragma: no cover - a copy has the same shape
        raise ValueError("the copy does not match the document")
    return same


def _by_id(tree: etree._ElementTree, identifier: str) -> etree._Element:
    matches = _BY_ID(tree, id=identifier)
    if len(matches) > 1:  # signature wrapping: two candidates for one reference (AM-06)
        raise _format(f"the identifier {identifier!r} appears {len(matches)} times")
    if not matches:
        raise _Result(
            Indication.INDETERMINATE, "SIGNED_DATA_NOT_FOUND", f"no element with Id {identifier!r}"
        )
    element: etree._Element = matches[0]
    return element


def _dereference(
    uri: str | None, tree: etree._ElementTree, external: bytes | None
) -> _NodeSet | bytes:
    if uri == "":
        return _NodeSet(copy.deepcopy(tree), None)
    if uri is not None and uri.startswith("#"):
        if uri.startswith("#xpointer("):
            raise _format(f"XPointer references are not supported: {uri}")
        clone, apex = _copy_of(tree, _by_id(tree, uri[1:]))
        return _NodeSet(clone, apex)
    if external is None:  # a detached reference whose file the caller did not give
        raise _Result(Indication.INDETERMINATE, "SIGNED_DATA_NOT_FOUND", f"the content of {uri!r}")
    return external


def _canonicalize(
    data: _NodeSet | bytes, algorithm: str, prefixes: Sequence[str] | None = None
) -> bytes:
    if isinstance(data, bytes):  # octets: parsed as XML first (XMLDSig §4.4.3.2)
        exclusive, comments = _CANONICALIZATIONS[algorithm]
        return bytes(
            etree.tostring(
                parse_document(data),
                method="c14n",
                exclusive=exclusive,
                with_comments=comments,
                inclusive_ns_prefixes=list(prefixes) if prefixes else None,
            )
        )
    if data.apex is None:  # the whole document; same-document references carry no comments
        exclusive, _ = _CANONICALIZATIONS[algorithm]
        return bytes(
            etree.tostring(
                data.tree,
                method="c14n",
                exclusive=exclusive,
                with_comments=False,  # lxml includes them unless told (review of 2026-11-01)
                inclusive_ns_prefixes=list(prefixes) if prefixes else None,
            )
        )
    return _c14n_of(data.apex, algorithm, prefixes, comments=False)


def _c14n_of(
    element: etree._Element,
    algorithm: str,
    prefixes: Sequence[str] | None = None,
    *,
    comments: bool | None = None,
) -> bytes:
    """The canonical form of ``element`` as a document subset. Inclusive C14N inherits the
    ``xml:`` attributes of the ancestors (C14N 1.0 §2.4; 1.1 only ``xml:lang`` and
    ``xml:space``), which lxml leaves out for a subtree: they are copied onto the apex here.
    C14N 1.1 fixes up an inherited ``xml:base``, which is not supported."""
    exclusive, with_comments = _CANONICALIZATIONS[algorithm]
    if comments is not None:
        with_comments = comments
    target = element
    if not exclusive:
        inherited: dict[str, str] = {}
        for ancestor in element.iterancestors():  # the nearest value wins
            for name, value in ancestor.attrib.items():
                if name.startswith(f"{{{_XML_NS}}}") and name not in inherited:
                    inherited[name] = value
        if algorithm.startswith(_C14N11):
            if f"{{{_XML_NS}}}base" in inherited:
                raise _format("C14N 1.1 of a subset under an xml:base")
            inherited.pop(f"{{{_XML_NS}}}id", None)
        missing = {name: v for name, v in inherited.items() if name not in element.attrib}
        if missing:
            target = copy.deepcopy(element)
            for name, value in missing.items():
                target.set(name, value)
    return bytes(
        etree.tostring(
            target,
            method="c14n",
            exclusive=exclusive,
            with_comments=with_comments,
            inclusive_ns_prefixes=list(prefixes) if prefixes else None,
        )
    )


def _prefixes(transform: etree._Element) -> list[str] | None:
    inclusive = transform.find(f"{{{_EXC_C14N}}}InclusiveNamespaces")
    return None if inclusive is None else inclusive.get("PrefixList", "").split()


def _remove(node_set: _NodeSet, element: etree._Element) -> None:
    """Remove ``element`` (an element of the copy) if it is inside the node-set."""
    inside = (
        node_set.apex is None
        or element is node_set.apex
        or any(ancestor is node_set.apex for ancestor in element.iterancestors())
    )
    parent = element.getparent()
    if not inside or parent is None:
        return
    if element.tail:  # the text after the element is not part of it: lxml would drop it
        previous = element.getprevious()
        if previous is not None:
            previous.tail = (previous.tail or "") + element.tail
        else:
            parent.text = (parent.text or "") + element.tail
        element.tail = None
    parent.remove(element)
    if not _is_bare_signature(element):
        node_set.excludes_content = True


def _is_bare_signature(element: etree._Element) -> bool:
    """A ``ds:Signature`` that carries no document content: ``SignedInfo``, ``SignatureValue``
    and only the ``ds:Object`` of its qualifying properties. Anything else that a transform
    removes (a fake signature that wraps a clause, AM-06) is content left unsigned."""
    if element.tag != _SIGNATURE:
        return False
    if element.find("ds:SignedInfo", NS) is None or element.find("ds:SignatureValue", NS) is None:
        return False
    for obj in element.findall("ds:Object", NS):
        if (obj.text or "").strip() or any(
            isinstance(child.tag, str) and child.tag != f"{{{XADES}}}QualifyingProperties"
            for child in obj
        ):
            return False
    return True


def _subtract(node_set: _NodeSet, transform: etree._Element) -> None:
    """XPath Filter 2.0 with ``subtract`` only (what DSS and Firma Perú write: every
    ``ds:Signature``); ``intersect`` and ``union`` select what is signed and are refused."""
    for xpath in transform.findall(f"{{{_FILTER2}}}XPath"):
        if xpath.get("Filter") != "subtract":
            raise _format(f"XPath Filter 2.0 {xpath.get('Filter')!r} is not supported")
        namespaces = {prefix: uri for prefix, uri in xpath.nsmap.items() if prefix}
        selected = node_set.tree.xpath(xpath.text or "", namespaces=namespaces)
        if not isinstance(selected, list) or not all(
            isinstance(node, etree._Element) for node in selected
        ):
            raise _format("an XPath filter that selects something other than elements")
        for element in selected:
            _remove(node_set, element)


def _transformed(
    reference: etree._Element,
    sig: etree._Element,
    tree: etree._ElementTree,
    external: bytes | None,
    final: str = _C14N10,
) -> tuple[bytes, bool]:
    """The octets of ``reference`` after its transforms, and whether a transform removed
    content other than signatures. A node-set left at the end is canonicalized with
    ``final`` (C14N 1.0 for the digest, as XMLDSig says; the archive time-stamp's own)."""
    data = _dereference(reference.get("URI"), tree, external)
    excludes = False  # kept across the transforms: a canonicalization turns the node-set into
    # octets, and what the earlier transforms removed must still be reported (AM-06)
    for transform in reference.findall("ds:Transforms/ds:Transform", NS):
        algorithm = transform.get("Algorithm", "")
        if isinstance(data, _NodeSet):
            excludes = excludes or data.excludes_content
        if algorithm in _CANONICALIZATIONS:
            data = _canonicalize(data, algorithm, _prefixes(transform))
        elif algorithm == _BASE64:  # DSS's enveloping: the document, encoded in ds:Object
            data = _decoded(data)
        elif algorithm in (_ENVELOPED, _FILTER2) and isinstance(data, _NodeSet):
            if algorithm == _ENVELOPED:
                _remove(data, _own_copy(data, tree, sig))
            else:
                _subtract(data, transform)
        else:
            raise _format(f"unsupported transform {algorithm!r}")
    if isinstance(data, _NodeSet):
        excludes = excludes or data.excludes_content
        data = _canonicalize(data, final)
    return data, excludes


def _decoded(data: _NodeSet | bytes) -> bytes:
    """The base64 transform: the text of the node-set (or the octets), decoded."""
    if isinstance(data, _NodeSet):
        target = data.tree.getroot() if data.apex is None else data.apex
        data = "".join(target.itertext()).encode()
    return base64.b64decode(b"".join(data.split()), validate=True)


def _own_copy(node_set: _NodeSet, tree: etree._ElementTree, sig: etree._Element) -> Any:
    """The copy of ``sig`` in the node-set's private tree (the enveloped transform removes
    only the signature that the reference belongs to)."""
    return _same_in(node_set.tree, tree, sig)


class _Octets:
    """The output of every reference of one signature, computed once and shared by the
    scope, the digests and the archive time-stamps (each pass copies the document)."""

    def __init__(
        self, sig: etree._Element, tree: etree._ElementTree, external: bytes | None
    ) -> None:
        self.sig = sig
        self.tree = tree
        self.external = external
        self._memo: dict[tuple[etree._Element, str], tuple[bytes, bool]] = {}

    def of(self, reference: etree._Element, final: str = _C14N10) -> tuple[bytes, bool]:
        key = (reference, final)
        if key not in self._memo:
            self._memo[key] = _transformed(reference, self.sig, self.tree, self.external, final)
        return self._memo[key]


def _digest_name(method: etree._Element | None) -> str:
    algorithm = method.get("Algorithm") if method is not None else None
    name = _DIGEST_METHODS.get(algorithm or "")
    if name is None:
        raise _format(f"unsupported digest method {algorithm!r}")
    return name


def _check_references(sig: etree._Element, octets: _Octets) -> list[str]:
    """Every reference digests to its value, or TOTAL-FAILED/HASH_FAILURE. A weak digest
    is returned, not raised: an altered document is reported as altered first (§5.2.7)."""
    weak = []
    for reference in sig.findall("ds:SignedInfo/ds:Reference", NS):
        name = _digest_name(reference.find("ds:DigestMethod", NS))
        expected = base64.b64decode(_text(reference, "ds:DigestValue"))
        if hashlib.new(name, octets.of(reference)[0]).digest() != expected:
            raise _Result(
                Indication.TOTAL_FAILED, "HASH_FAILURE", f"reference {reference.get('URI')!r}"
            )
        if name in WEAK_DIGESTS:
            weak.append(f"reference digested with {name}")
    return weak


def _text(element: etree._Element, path: str) -> str:
    found = element.find(path, NS)
    if found is None or found.text is None:
        raise _format(f"missing {path}")
    return "".join(found.text.split())


# -- the signature value and the signing certificate ----------------------------------------


def _check_signature_value(sig: etree._Element, certificate: x509.Certificate) -> list[str]:
    """The signature value verifies, or TOTAL-FAILED/SIG_CRYPTO_FAILURE; as with the
    references, a weak algorithm or key is returned after the check, not before."""
    signed_info = sig.find("ds:SignedInfo", NS)
    method = sig.find("ds:SignedInfo/ds:SignatureMethod", NS)
    c14n = sig.find("ds:SignedInfo/ds:CanonicalizationMethod", NS)
    if signed_info is None or method is None or c14n is None:
        raise _format("incomplete SignedInfo")
    c14n_algorithm = c14n.get("Algorithm", "")
    if c14n_algorithm not in _CANONICALIZATIONS:
        raise _format(f"unsupported canonicalization {c14n_algorithm!r}")
    kind_digest = _SIGNATURE_METHODS.get(method.get("Algorithm", ""))
    if kind_digest is None:
        raise _format(f"unsupported signature method {method.get('Algorithm')!r}")
    kind, digest = kind_digest
    octets = _c14n_of(signed_info, c14n_algorithm, _prefixes(c14n))
    value = base64.b64decode(_text(sig, "ds:SignatureValue"))
    key = certificate.public_key()
    weak = [f"signature with {digest}"] if digest in WEAK_DIGESTS else []
    try:
        if kind == "rsa" and isinstance(key, rsa.RSAPublicKey):
            if key.key_size < MIN_RSA_BITS:
                weak.append(f"RSA key of {key.key_size} bits")
            key.verify(value, octets, padding.PKCS1v15(), _HASHES[digest]())
        elif kind == "ecdsa" and isinstance(key, ec.EllipticCurvePublicKey):
            half = len(value) // 2  # XMLDSig ECDSA: r and s concatenated, not DER
            der = encode_dss_signature(
                int.from_bytes(value[:half], "big"), int.from_bytes(value[half:], "big")
            )
            key.verify(der, octets, ec.ECDSA(_HASHES[digest]()))
        else:
            raise InvalidSignature("the key does not match the signature method")
    except InvalidSignature as exc:
        raise _Result(Indication.TOTAL_FAILED, "SIG_CRYPTO_FAILURE", str(exc)) from exc
    return weak


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
        raise _format("no QualifyingProperties that target the signature")
    signed = qualifying[0].find("xades:SignedProperties", NS)
    if signed is None:
        raise _format("no SignedProperties")
    covered = any(
        reference.get("Type") == _SIGNED_PROPERTIES
        and (reference.get("URI") or "").startswith("#")
        and _by_id(tree, (reference.get("URI") or "")[1:]) is signed
        for reference in sig.findall("ds:SignedInfo/ds:Reference", NS)
    )
    if not covered:
        raise _format("the SignedProperties are not signed")
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
        raise _Result(
            Indication.INDETERMINATE, "NO_SIGNING_CERTIFICATE_FOUND", "no SigningCertificate"
        )
    name = _digest_name(cert.find("xades:CertDigest/ds:DigestMethod", NS))
    expected = base64.b64decode(_text(cert, "xades:CertDigest/ds:DigestValue"))
    for candidate in candidates:
        der = candidate.public_bytes(Encoding.DER)
        if hashlib.new(name, der).digest() == expected:
            return candidate
    raise _Result(
        Indication.INDETERMINATE, "NO_SIGNING_CERTIFICATE_FOUND", "no certificate matches"
    )


# -- time-stamps ----------------------------------------------------------------------------


def _token(element: etree._Element) -> tuple[cms.SignedData, str]:
    """The ``SignedData`` of an ``EncapsulatedTimeStamp`` and the hash of its imprint."""
    raw = base64.b64decode(_text(element, "xades:EncapsulatedTimeStamp"))
    signed_data: cms.SignedData = cms.ContentInfo.load(raw)["content"]
    info = signed_data["encap_content_info"]["content"].parsed
    algorithm: str = info["message_imprint"]["hash_algorithm"]["algorithm"].native
    return signed_data, algorithm


def _timestamp_c14n(element: etree._Element) -> str:
    method = element.find("ds:CanonicalizationMethod", NS)
    algorithm = _C14N10 if method is None else method.get("Algorithm", "")
    if algorithm not in _CANONICALIZATIONS:
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
        imprint = hashlib.new(algorithm, _c14n_of(value, _timestamp_c14n(element))).digest()
        return timestamp_report(validate_timestamp(token, imprint, spec, context.timing))
    except _Result as result:  # e.g. no EncapsulatedTimeStamp: only the time-stamp fails
        return TimestampReport(result.indication, result.subindication, None, None)
    except _UNREADABLE:
        return TimestampReport(Indication.TOTAL_FAILED, "FORMAT_FAILURE", None, None)


def _archive_octets(
    sig: etree._Element, archive: etree._Element, octets: _Octets, algorithm: str
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
            pieces.append(_c14n_of(element, algorithm))
    preceding: list[bytes] = []
    for element in archive.itersiblings(preceding=True):  # nearest first: reversed below
        if isinstance(element.tag, str):  # elements only, not comments
            preceding.append(_c14n_of(element, algorithm))
    pieces.extend(reversed(preceding))
    for obj in sig.findall("ds:Object", NS):
        if obj.find("xades:QualifyingProperties", NS) is None:
            pieces.append(_c14n_of(obj, algorithm))
    return b"".join(pieces)


def _archive_timestamp(
    sig: etree._Element,
    archive: etree._Element,
    octets: _Octets,
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
    except _Result as result:
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
            matches = _BY_ID(tree, id=uri[1:])
            if len(matches) == 1 and _is_object(matches[0], sig):
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
        if reference.get("Type") == _SIGNED_PROPERTIES:
            continue
        if uri is not None and uri.startswith("#") and not uri.startswith("#xpointer("):
            matches = _BY_ID(tree, id=uri[1:])
            if (
                len(matches) == 1
                and _is_inside(matches[0], sig)
                and not _is_object(matches[0], sig)
            ):
                continue
        data.append(reference)
    return data


def _is_inside(element: etree._Element, sig: etree._Element) -> bool:
    return element is sig or any(ancestor is sig for ancestor in element.iterancestors())


def _is_object(element: etree._Element, sig: etree._Element) -> bool:
    """Whether ``element`` is a ``ds:Object`` of ``sig`` (or inside one) other than the one
    of the ``QualifyingProperties``."""
    for node in (element, *element.iterancestors()):
        if node.tag == _OBJECT and node.getparent() is sig:
            return node.find("xades:QualifyingProperties", NS) is None
    return False


def _scope(
    sig: etree._Element, tree: etree._ElementTree, packaging: XadesPackaging, octets: _Octets
) -> SignedScope:
    if packaging is XadesPackaging.ENVELOPING:
        return SignedScope.OBJECT
    if packaging is XadesPackaging.DETACHED:
        return SignedScope.EXTERNAL
    root = tree.getroot()
    for reference in _data_references(sig, tree):
        uri = reference.get("URI")
        whole = uri == "" or (
            uri is not None and uri.startswith("#") and _BY_ID(tree, id=uri[1:]) == [root]
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
    result: _Result,
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
    octets = _Octets(sig, tree, external if len(outside) <= 1 else None)
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
        weak = _check_references(sig, octets) + _check_signature_value(sig, signer)
        if weak:
            raise _weak("; ".join(weak))
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
    except _Result as result:
        return _failed(packaging, result, signer, claimed, scope, references)
    except _UNREADABLE as exc:
        return _failed(packaging, _format(str(exc)), signer, claimed, scope, references)
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
        for sig in tree.getroot().iter(_SIGNATURE)
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
