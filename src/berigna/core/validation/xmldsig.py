# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The XMLDSig layer of the XAdES verifier (:mod:`berigna.core.validation.xades`): the
cryptographic verification of a ``ds:Signature`` (ETSI EN 319 102-1 §5.2.7).

Every reference is dereferenced and transformed here, with an allow-list of transforms
(enveloped signature, XPath Filter 2.0 ``subtract``, base64, the canonicalizations), and
digested; then ``SignatureValue`` over the canonicalized ``SignedInfo``. A difference is
TOTAL-FAILED/HASH_FAILURE or SIG_CRYPTO_FAILURE; SHA-1, MD5 and RSA under 2048 bits are
returned as weak, for the caller to report INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE once it
knows the document is unaltered (ACR-18).

XML Signature Wrapping (AM-06, CS-06): references are resolved strictly — an ``Id`` that
appears twice is a format failure, never "the first one" — and each transformed reference
says whether a transform removed content other than signatures, from which the verifier
derives what the signature covers.

A failed step raises :class:`Result`, which carries its ETSI indication.
"""

import base64
import copy
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from lxml import etree

from berigna.core.formats.xades import DS, NS, XADES, parse_document
from berigna.core.validation.algorithms import MIN_RSA_BITS, WEAK_DIGESTS
from berigna.core.validation.spec import Indication

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
C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
_C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
# algorithm -> (exclusive, with comments)
CANONICALIZATIONS = {
    C14N10: (False, False),
    f"{C14N10}#WithComments": (False, True),
    _C14N11: (False, False),
    f"{_C14N11}#WithComments": (False, True),
    _EXC_C14N: (True, False),
    f"{_EXC_C14N}WithComments": (True, True),
}
_ENVELOPED = f"{DS}enveloped-signature"
_FILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2"
_BASE64 = f"{DS}base64"
SIGNED_PROPERTIES = "http://uri.etsi.org/01903#SignedProperties"
_XML_NS = "http://www.w3.org/XML/1998/namespace"
SIGNATURE = f"{{{DS}}}Signature"
OBJECT = f"{{{DS}}}Object"
# Id, ID and id: the names that DSS (Santuario) registers as identifiers too. An identifier
# that two elements share is refused (AM-06), whatever its spelling.
BY_ID = etree.XPath("//*[@Id=$id or @ID=$id or @id=$id]")


class Result(Exception):
    """An ETSI result reached before the end of the process (a failed step)."""

    def __init__(self, indicate: Indication, subindication: str, reason: str) -> None:
        super().__init__(reason)
        self.indication = indicate
        self.subindication = subindication


def format_failure(reason: str) -> Result:
    return Result(Indication.TOTAL_FAILED, "FORMAT_FAILURE", reason)


def weak_failure(reason: str) -> Result:
    return Result(Indication.INDETERMINATE, "CRYPTO_CONSTRAINTS_FAILURE", reason)


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


def by_id(tree: etree._ElementTree, identifier: str) -> etree._Element:
    matches = BY_ID(tree, id=identifier)
    if len(matches) > 1:  # signature wrapping: two candidates for one reference (AM-06)
        raise format_failure(f"the identifier {identifier!r} appears {len(matches)} times")
    if not matches:
        raise Result(
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
            raise format_failure(f"XPointer references are not supported: {uri}")
        clone, apex = _copy_of(tree, by_id(tree, uri[1:]))
        return _NodeSet(clone, apex)
    if external is None:  # a detached reference whose file the caller did not give
        raise Result(Indication.INDETERMINATE, "SIGNED_DATA_NOT_FOUND", f"the content of {uri!r}")
    return external


def _canonicalize(
    data: _NodeSet | bytes, algorithm: str, prefixes: Sequence[str] | None = None
) -> bytes:
    if isinstance(data, bytes):  # octets: parsed as XML first (XMLDSig §4.4.3.2)
        exclusive, comments = CANONICALIZATIONS[algorithm]
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
        exclusive, _ = CANONICALIZATIONS[algorithm]
        return bytes(
            etree.tostring(
                data.tree,
                method="c14n",
                exclusive=exclusive,
                with_comments=False,  # lxml includes them unless told (review of 2026-11-01)
                inclusive_ns_prefixes=list(prefixes) if prefixes else None,
            )
        )
    return c14n_of(data.apex, algorithm, prefixes, comments=False)


def c14n_of(
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
    exclusive, with_comments = CANONICALIZATIONS[algorithm]
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
                raise format_failure("C14N 1.1 of a subset under an xml:base")
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
    if element.tag != SIGNATURE:
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
            raise format_failure(f"XPath Filter 2.0 {xpath.get('Filter')!r} is not supported")
        namespaces = {prefix: uri for prefix, uri in xpath.nsmap.items() if prefix}
        selected = node_set.tree.xpath(xpath.text or "", namespaces=namespaces)
        if not isinstance(selected, list) or not all(
            isinstance(node, etree._Element) for node in selected
        ):
            raise format_failure("an XPath filter that selects something other than elements")
        for element in selected:
            _remove(node_set, element)


def _transformed(
    reference: etree._Element,
    sig: etree._Element,
    tree: etree._ElementTree,
    external: bytes | None,
    final: str = C14N10,
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
        if algorithm in CANONICALIZATIONS:
            data = _canonicalize(data, algorithm, _prefixes(transform))
        elif algorithm == _BASE64:  # DSS's enveloping: the document, encoded in ds:Object
            data = _decoded(data)
        elif algorithm in (_ENVELOPED, _FILTER2) and isinstance(data, _NodeSet):
            if algorithm == _ENVELOPED:
                _remove(data, _own_copy(data, tree, sig))
            else:
                _subtract(data, transform)
        else:
            raise format_failure(f"unsupported transform {algorithm!r}")
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


class Octets:
    """The output of every reference of one signature, computed once and shared by the
    scope, the digests and the archive time-stamps (each pass copies the document)."""

    def __init__(
        self, sig: etree._Element, tree: etree._ElementTree, external: bytes | None
    ) -> None:
        self.sig = sig
        self.tree = tree
        self.external = external
        self._memo: dict[tuple[etree._Element, str], tuple[bytes, bool]] = {}

    def of(self, reference: etree._Element, final: str = C14N10) -> tuple[bytes, bool]:
        key = (reference, final)
        if key not in self._memo:
            self._memo[key] = _transformed(reference, self.sig, self.tree, self.external, final)
        return self._memo[key]


def digest_name(method: etree._Element | None) -> str:
    algorithm = method.get("Algorithm") if method is not None else None
    name = _DIGEST_METHODS.get(algorithm or "")
    if name is None:
        raise format_failure(f"unsupported digest method {algorithm!r}")
    return name


def check_references(sig: etree._Element, octets: Octets) -> list[str]:
    """Every reference digests to its value, or TOTAL-FAILED/HASH_FAILURE. A weak digest
    is returned, not raised: an altered document is reported as altered first (§5.2.7)."""
    weak = []
    for reference in sig.findall("ds:SignedInfo/ds:Reference", NS):
        name = digest_name(reference.find("ds:DigestMethod", NS))
        expected = base64.b64decode(text_of(reference, "ds:DigestValue"))
        if hashlib.new(name, octets.of(reference)[0]).digest() != expected:
            raise Result(
                Indication.TOTAL_FAILED, "HASH_FAILURE", f"reference {reference.get('URI')!r}"
            )
        if name in WEAK_DIGESTS:
            weak.append(f"reference digested with {name}")
    return weak


def text_of(element: etree._Element, path: str) -> str:
    found = element.find(path, NS)
    if found is None or found.text is None:
        raise format_failure(f"missing {path}")
    return "".join(found.text.split())


# -- the signature value ------------------------------------------------------------------


def check_signature_value(sig: etree._Element, certificate: x509.Certificate) -> list[str]:
    """The signature value verifies, or TOTAL-FAILED/SIG_CRYPTO_FAILURE; as with the
    references, a weak algorithm or key is returned after the check, not before."""
    signed_info = sig.find("ds:SignedInfo", NS)
    method = sig.find("ds:SignedInfo/ds:SignatureMethod", NS)
    c14n = sig.find("ds:SignedInfo/ds:CanonicalizationMethod", NS)
    if signed_info is None or method is None or c14n is None:
        raise format_failure("incomplete SignedInfo")
    c14n_algorithm = c14n.get("Algorithm", "")
    if c14n_algorithm not in CANONICALIZATIONS:
        raise format_failure(f"unsupported canonicalization {c14n_algorithm!r}")
    kind_digest = _SIGNATURE_METHODS.get(method.get("Algorithm", ""))
    if kind_digest is None:
        raise format_failure(f"unsupported signature method {method.get('Algorithm')!r}")
    kind, digest = kind_digest
    octets = c14n_of(signed_info, c14n_algorithm, _prefixes(c14n))
    value = base64.b64decode(text_of(sig, "ds:SignatureValue"))
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
        raise Result(Indication.TOTAL_FAILED, "SIG_CRYPTO_FAILURE", str(exc)) from exc
    return weak
