# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Synthetic ETSI trusted lists signed by a test "INDECOPI" root (ADR-0014 tests)."""

import base64
import datetime as dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml.signer import XMLSigner

from support.pki import NOW

TSL_NS = "http://uri.etsi.org/02231/v2#"
UNDER_SUPERVISION = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"
WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/No acredited"
CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _usage(**flags: bool) -> x509.KeyUsage:
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    )
    return x509.KeyUsage(**{n: flags.get(n, False) for n in names})


@dataclass
class TslPki:
    root: x509.Certificate
    root_key: rsa.RSAPrivateKey
    signer: x509.Certificate
    signer_key: rsa.RSAPrivateKey

    def crl(self, *, revoked: bool = False, key: rsa.RSAPrivateKey | None = None) -> bytes:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.root.subject)
            .last_update(NOW - dt.timedelta(hours=1))
            .next_update(NOW + dt.timedelta(days=1))
        )
        if revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(self.signer.serial_number)
                .revocation_date(NOW - dt.timedelta(hours=2))
                .build()
            )
        crl = builder.sign(key or self.root_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.DER)


def build_tsl_pki(
    *,
    signer_usage: x509.KeyUsage | None = None,
    key_usage: bool = True,
    signer_days: tuple[int, int] = (-1, 365),
    crl_urls: tuple[str, ...] = ("https://crl.example/tsl.crl",),
) -> TslPki:
    root_key, signer_key = _key(), _key()
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("TEST INDECOPI AAC RAIZ"))
        .issuer_name(_name("TEST INDECOPI AAC RAIZ"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=30))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .sign(root_key, hashes.SHA256())
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("TEST TSL Suscriptor"))
        .issuer_name(root.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + dt.timedelta(days=signer_days[0]))
        .not_valid_after(NOW + dt.timedelta(days=signer_days[1]))
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint([x509.UniformResourceIdentifier(url)], None, None, None)
                    for url in crl_urls
                ]
            ),
            critical=False,
        )
    )
    if key_usage:
        builder = builder.add_extension(signer_usage or _usage(digital_signature=True), True)
    return TslPki(root, root_key, builder.sign(root_key, hashes.SHA256()), signer_key)


@dataclass
class Service:
    certificate: x509.Certificate
    status: str = UNDER_SUPERVISION
    provider: str = "PRESTADOR DE PRUEBAS"
    name: str = "SERVICIO DE PRUEBAS"
    service_type: str = CA_QC


@dataclass
class TslContent:
    services: list[Service] = field(default_factory=list)
    sequence: int = 7
    issued: str = (NOW - dt.timedelta(days=1)).isoformat().replace("+00:00", "Z")
    next_update: str = (NOW + dt.timedelta(days=180)).isoformat().replace("+00:00", "Z")
    with_scheme: bool = True


def _sub(parent: etree._Element, tag: str, text: str | None = None) -> etree._Element:
    element = etree.SubElement(parent, f"{{{TSL_NS}}}{tag}")
    if text is not None:
        element.text = text
    return element


def unsigned_tsl(content: TslContent) -> etree._Element:
    root = etree.Element(f"{{{TSL_NS}}}TrustServiceStatusList", nsmap={"tsl": TSL_NS})
    root.set("Id", "tsl-pruebas")
    if content.with_scheme:
        scheme = _sub(root, "SchemeInformation")
        _sub(scheme, "TSLVersionIdentifier", "5")
        _sub(scheme, "TSLSequenceNumber", str(content.sequence))
        _sub(_sub(scheme, "SchemeOperatorName"), "Name", "INDECOPI DE PRUEBAS")
        _sub(scheme, "ListIssueDateTime", content.issued)
        _sub(_sub(scheme, "NextUpdate"), "dateTime", content.next_update)
    providers = _sub(root, "TrustServiceProviderList")
    for service in content.services:
        provider = _sub(providers, "TrustServiceProvider")
        _sub(_sub(_sub(provider, "TSPInformation"), "TSPName"), "Name", service.provider)
        info = _sub(_sub(_sub(provider, "TSPServices"), "TSPService"), "ServiceInformation")
        _sub(info, "ServiceTypeIdentifier", service.service_type)
        _sub(_sub(info, "ServiceName"), "Name", service.name)
        der = service.certificate.public_bytes(serialization.Encoding.DER)
        digital_id = _sub(_sub(info, "ServiceDigitalIdentity"), "DigitalId")
        _sub(digital_id, "X509Certificate", base64.b64encode(der).decode())
        _sub(info, "ServiceStatus", service.status)
    return root


def sign_tsl(
    root: etree._Element,
    pki: TslPki,
    *,
    reference_uri: str = "#tsl-pruebas",
    digest: str = "sha256",
) -> bytes:
    signer = XMLSigner(
        signature_algorithm="rsa-sha256",
        digest_algorithm=digest,
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    )
    signed = signer.sign(
        root,
        key=pki.signer_key,
        cert=[pki.signer.public_bytes(serialization.Encoding.PEM).decode()],
        reference_uri=reference_uri,
    )
    return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")


def build_tsl(pki: TslPki, content: TslContent | None = None) -> bytes:
    return sign_tsl(unsigned_tsl(content or TslContent()), pki)
