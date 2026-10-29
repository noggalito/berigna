# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The INDECOPI trusted list (TSL) as a source of trust anchors (ADR-0014).

INDECOPI publishes the Peruvian TSL (ETSI TS 119 612, scheme territory PE) at :data:`TSL_URL`,
signed by a "TSL Suscriptor" certificate issued by INDECOPI AAC RAIZ. That root is pinned here:
its certificate ships with the package (``tsl/indecopi-aac-raiz.crt``, obtained from
``recursos.indecopi.gob.pe``, the address in the signer's AIA) and its SHA-256 is fixed in
:data:`TSL_ROOT_SHA256`, so a replaced file is refused.

Checks, in this order, before anything in the list is trusted:

1. size limit, and an XML parser that resolves no entities and fetches nothing;
2. the signer certificate in the signature is issued by the pinned root, both are valid at the
   given moment, the signer may sign (key usage) and, when a CRL of the root is supplied, it
   is not revoked;
3. the XML signature verifies with that certificate (signxml), and one of its references,
   with SHA-256 or stronger, covers the whole list. Only that signed element is read
   afterwards, never the downloaded document, which defeats signature wrapping;
4. the list is current (``NextUpdate`` not passed) and, when the caller knows the last
   sequence number it accepted, not older (rollback).

From the services in an accepted status, the CA certificates become trust anchors with origin
"TSL": self-issued ones as roots, the others as intermediates.
"""

import base64
import datetime as dt
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Any

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from lxml import etree
from signxml.algorithms import DigestAlgorithm
from signxml.exceptions import InvalidInput
from signxml.exceptions import InvalidSignature as XmlInvalidSignature
from signxml.verifier import SignatureConfiguration, XMLVerifier

from berigna.core.certs import to_asn1
from berigna.core.errors import TrustStoreIntegrityError, TslError, TslExpiredError
from berigna.core.trust.store import (
    TrustedCertificate,
    TrustStore,
    _fingerprint,
)

TSL_URL = "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml"
TSL_ROOT_SHA256 = "6cf85e75ca1cf9d560fdc5ebaff30cea157cde223a068c3e1e051d123d5f9375"
MAX_TSL_SIZE = 5 * 1024 * 1024  # bytes; the 2026 list is ~350 KB

_TSL = "http://uri.etsi.org/02231/v2#"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_NS = {"tsl": _TSL, "ds": _DS}
_STRONG_DIGESTS = {
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512",
}
# Last path segment of ServiceStatus, lower case. INDECOPI uses "undersupervision" for active
# services and "No acredited" for withdrawn ones; the ETSI values are accepted as well.
ACCEPTED_STATUSES = frozenset(
    {"undersupervision", "accredited", "granted", "recognisedatnationallevel"}
)
_MAX_REFERENCES = 8


@dataclass(frozen=True)
class TslService:
    provider: str
    name: str
    service_type: str  # last segment of ServiceTypeIdentifier, e.g. "CA/QC"
    status: str  # last segment of ServiceStatus
    certificates: tuple[x509.Certificate, ...]

    @property
    def accepted(self) -> bool:
        return self.status.lower() in ACCEPTED_STATUSES


@dataclass(frozen=True)
class TrustedList:
    sequence_number: int
    issued: dt.datetime
    next_update: dt.datetime
    operator: str
    signer: x509.Certificate
    services: tuple[TslService, ...]

    def ca_certificates(self) -> list[x509.Certificate]:
        """CA certificates of the accepted services, without duplicates."""
        seen: dict[str, x509.Certificate] = {}
        for service in self.services:
            if service.accepted:
                for certificate in service.certificates:
                    if _ca_flags(certificate)[0]:
                        seen.setdefault(_fingerprint(certificate), certificate)
        return list(seen.values())


def _ca_flags(certificate: x509.Certificate) -> tuple[bool, bool]:
    """(is a CA, is self-issued), read with asn1crypto.

    Some accredited roots in the 2026 list (GSE, Certicámara) carry extensions that cryptography
    refuses to parse (a UserNotice with an invalid string type); asn1crypto, which the signature
    validator also uses, reads them.
    """
    parsed = to_asn1(certificate)
    return bool(parsed.ca), bool(parsed.self_issued)


def tsl_root() -> x509.Certificate:
    """The pinned INDECOPI AAC RAIZ certificate; a file that does not match is refused."""
    data = files("berigna.core.trust").joinpath("tsl/indecopi-aac-raiz.crt").read_bytes()
    certificate = x509.load_pem_x509_certificate(data)
    if _fingerprint(certificate) != TSL_ROOT_SHA256:
        raise TrustStoreIntegrityError("the pinned root of the trusted list has been altered")
    return certificate


def _parse(data: bytes) -> Any:
    if len(data) > MAX_TSL_SIZE:
        raise TslError(f"trusted list larger than {MAX_TSL_SIZE} bytes")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise TslError(f"the trusted list is not well-formed XML: {exc}") from exc


def _signature(root: Any) -> Any:
    signatures = root.findall(f"{{{_DS}}}Signature")
    if len(signatures) != 1:
        raise TslError("the trusted list must carry exactly one enveloped signature")
    return signatures[0]


def _signer_certificate(signature: Any) -> x509.Certificate:
    encoded = signature.findtext("ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=_NS)
    if not encoded:
        raise TslError("the signature does not carry the signer certificate")
    try:
        return x509.load_der_x509_certificate(base64.b64decode(encoded))
    except ValueError as exc:
        raise TslError(f"unreadable signer certificate: {exc}") from exc


def _check_signer(
    signer: x509.Certificate,
    root: x509.Certificate,
    moment: dt.datetime,
    crl: bytes | None,
) -> None:
    try:
        signer.verify_directly_issued_by(root)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise TslError("the trusted list is not signed under INDECOPI AAC RAIZ") from exc
    for certificate in (root, signer):
        if not certificate.not_valid_before_utc <= moment <= certificate.not_valid_after_utc:
            raise TslError(f"{certificate.subject.rfc4514_string()} is not valid at {moment}")
    try:
        usage = signer.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise TslError("the signer certificate does not state its key usage") from exc
    if not (usage.digital_signature or usage.content_commitment):
        raise TslError("the signer certificate may not sign")
    if crl is not None:
        _check_not_revoked(signer, root, moment, crl)


def _check_not_revoked(
    signer: x509.Certificate, root: x509.Certificate, moment: dt.datetime, data: bytes
) -> None:
    try:
        crl = x509.load_der_x509_crl(data)
    except ValueError:
        try:
            crl = x509.load_pem_x509_crl(data)
        except ValueError as exc:
            raise TslError(f"unreadable CRL of the trusted list signer: {exc}") from exc
    if crl.issuer != root.subject or not crl.is_signature_valid(root.public_key()):  # type: ignore[arg-type]
        raise TslError("the CRL of the trusted list signer is not signed by its root")
    if crl.next_update_utc is not None and crl.next_update_utc < moment:
        raise TslError("the CRL of the trusted list signer is out of date")
    if crl.get_revoked_certificate_by_serial_number(signer.serial_number) is not None:
        raise TslError("the trusted list signer certificate has been revoked")


def _verified_list(data: bytes, root_element: Any, signer: x509.Certificate) -> Any:
    signature = _signature(root_element)
    references = signature.findall("ds:SignedInfo/ds:Reference", namespaces=_NS)
    if not 1 <= len(references) <= _MAX_REFERENCES:
        raise TslError("unexpected number of signature references")
    config = SignatureConfiguration(
        expect_references=len(references),
        # A SHA-1 digest is tolerated only on references that are not the list itself: the
        # INDECOPI list digests its signing certificate with SHA-1, a certificate berigna
        # checks on its own against the pinned root.
        digest_algorithms=frozenset(DigestAlgorithm),
    )
    try:
        results = XMLVerifier().verify(data, x509_cert=signer, expect_config=config)
    except (InvalidInput, XmlInvalidSignature, ValueError) as exc:
        raise TslError(f"the signature of the trusted list does not verify: {exc}") from exc
    if not isinstance(results, list):
        results = [results]
    # signxml returns one result per reference, in SignedInfo order.
    whole_list = {"", f"#{root_element.get('Id')}"}
    for reference, result in zip(references, results, strict=True):
        digest = reference.find("ds:DigestMethod", namespaces=_NS).get("Algorithm")
        element = result.signed_xml
        if (
            reference.get("URI") in whole_list
            and digest in _STRONG_DIGESTS
            and element is not None
            and etree.QName(element).localname == "TrustServiceStatusList"
        ):
            return element  # the signed content, not the downloaded document
    raise TslError("no signature reference with SHA-256 or stronger covers the whole list")


def _text(element: Any, path: str) -> str:
    return (element.findtext(path, namespaces=_NS) or "").strip()


def _datetime(value: str) -> dt.datetime:
    moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.UTC)


def _services(signed: Any) -> tuple[TslService, ...]:
    services = []
    for provider in signed.iterfind(".//tsl:TrustServiceProvider", namespaces=_NS):
        provider_name = _text(provider, "tsl:TSPInformation/tsl:TSPName/tsl:Name")
        for service in provider.iterfind(".//tsl:TSPService", namespaces=_NS):
            info = service.find("tsl:ServiceInformation", namespaces=_NS)
            certificates = []
            for encoded in info.iterfind(
                "tsl:ServiceDigitalIdentity/tsl:DigitalId/tsl:X509Certificate", namespaces=_NS
            ):
                try:
                    certificates.append(
                        x509.load_der_x509_certificate(base64.b64decode(encoded.text or ""))
                    )
                except ValueError:
                    continue  # an unreadable entry is skipped, never trusted
            services.append(
                TslService(
                    provider=provider_name,
                    name=_text(info, "tsl:ServiceName/tsl:Name"),
                    service_type=_text(info, "tsl:ServiceTypeIdentifier").split("Svctype/")[-1],
                    status=_text(info, "tsl:ServiceStatus").rsplit("/", 1)[-1],
                    certificates=tuple(certificates),
                )
            )
    return tuple(services)


def load_tsl(
    data: bytes,
    *,
    moment: dt.datetime | None = None,
    signer_crl: bytes | None = None,
    minimum_sequence: int | None = None,
    root: x509.Certificate | None = None,
) -> TrustedList:
    """Verify and read a trusted list (see the module docstring for the checks).

    Raises :class:`~berigna.core.errors.TslError` when the list must not be used and
    :class:`~berigna.core.errors.TslExpiredError` when it is past its ``NextUpdate``.
    """
    when = moment or dt.datetime.now(dt.UTC)
    anchor = root or tsl_root()
    document = _parse(data)
    if etree.QName(document).localname != "TrustServiceStatusList":
        raise TslError("not an ETSI trusted list")
    signer = _signer_certificate(_signature(document))
    _check_signer(signer, anchor, when, signer_crl)
    signed = _verified_list(data, document, signer)

    scheme = signed.find("tsl:SchemeInformation", namespaces=_NS)
    if scheme is None:
        raise TslError("the trusted list has no scheme information")
    try:
        sequence = int(_text(scheme, "tsl:TSLSequenceNumber"))
        issued = _datetime(_text(scheme, "tsl:ListIssueDateTime"))
        next_update = _datetime(_text(scheme, "tsl:NextUpdate/tsl:dateTime"))
    except ValueError as exc:
        raise TslError(f"unreadable scheme information: {exc}") from exc
    if next_update < when:
        raise TslExpiredError(f"the trusted list expired on {next_update.isoformat()}")
    if minimum_sequence is not None and sequence < minimum_sequence:
        raise TslError(
            f"trusted list {sequence} is older than the one accepted ({minimum_sequence})"
        )
    return TrustedList(
        sequence_number=sequence,
        issued=issued,
        next_update=next_update,
        operator=_text(scheme, "tsl:SchemeOperatorName/tsl:Name"),
        signer=signer,
        services=_services(signed),
    )


def extend_store(store: TrustStore, trusted_list: TrustedList) -> TrustStore:
    """``store`` plus the CA certificates of ``trusted_list`` it does not have yet."""
    known = {entry.sha256 for entry in store.entries}
    extra = [
        TrustedCertificate(cert, "root" if _ca_flags(cert)[1] else "intermediate", "TSL")
        for cert in trusted_list.ca_certificates()
        if _fingerprint(cert) not in known
    ]
    return TrustStore((*store.entries, *extra))


def _download(url: str, timeout: float, limit: int) -> bytes:
    if not url.startswith("https://"):
        raise TslError(f"refusing a non-HTTPS URL: {url}")
    try:
        with requests.get(url, timeout=timeout, stream=True) as response:
            if response.status_code != 200:
                raise TslError(f"{url}: HTTP {response.status_code}")
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > limit:
                    raise TslError(f"{url}: larger than {limit} bytes")
                chunks.append(chunk)
    except OSError as exc:
        raise TslError(f"cannot download {url}: {exc}") from exc
    return b"".join(chunks)


def _crl_urls(signer: x509.Certificate) -> Sequence[str]:
    try:
        points = signer.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return []
    return [
        name.value
        for point in points
        for name in (point.full_name or [])
        if isinstance(name, x509.UniformResourceIdentifier) and name.value.startswith("https://")
    ]


def fetch_tsl(
    *, url: str = TSL_URL, timeout: float = 30.0, minimum_sequence: int | None = None
) -> tuple[TrustedList, bytes]:
    """Download, verify and read the current trusted list, with the signer's CRL.

    Returns the list and its bytes, which :mod:`berigna.core.trust.cache` keeps.
    """
    data = _download(url, timeout, MAX_TSL_SIZE)
    signer = _signer_certificate(_signature(_parse(data)))
    urls = _crl_urls(signer)
    if not urls:
        raise TslError("the trusted list signer has no HTTPS CRL distribution point")
    failures: list[TslError] = []
    for url in urls:  # every published distribution point, in order (R-17)
        try:
            crl = _download(url, timeout, 1024 * 1024)
            break
        except TslError as exc:
            failures.append(exc)
    else:
        raise failures[-1]
    return load_tsl(data, signer_crl=crl, minimum_sequence=minimum_sequence), data


def describe(trusted_list: TrustedList) -> str:
    """One line for logs: sequence, dates and the fingerprint of the signer."""
    digest = hashlib.sha256(trusted_list.signer.public_bytes(serialization.Encoding.DER))
    return (
        f"TSL {trusted_list.sequence_number} issued {trusted_list.issued.isoformat()} "
        f"next update {trusted_list.next_update.isoformat()} signer {digest.hexdigest()[:16]}"
    )
