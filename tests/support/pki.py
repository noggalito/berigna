# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Test PKI shaped like the IOFE (root -> CA with ARL -> signers with OCSP) and a tiny PDF."""

import datetime as dt
import io
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from berigna.core.trust import TrustedCertificate, TrustStore

NOW = dt.datetime.now(dt.UTC).replace(microsecond=0)
OCSP_URL = "http://127.0.0.1:9/ocsp"  # never contacted: tests run offline
CRL_URL = "http://127.0.0.1:9/arl.crl"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


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
class Pki:
    root: x509.Certificate
    root_key: rsa.RSAPrivateKey
    ca: x509.Certificate
    ca_key: rsa.RSAPrivateKey
    store: TrustStore

    def leaf(
        self,
        cn: str,
        *,
        days: tuple[int, int] = (-1, 365),
        non_repudiation: bool = True,
        key: rsa.RSAPrivateKey | None = None,
    ) -> x509.Certificate:
        key = key or _key()
        usage = (
            _usage(content_commitment=True) if non_repudiation else _usage(digital_signature=True)
        )
        return (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(self.ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW + dt.timedelta(days=days[0]))
            .not_valid_after(NOW + dt.timedelta(days=days[1]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(usage, critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier(OCSP_URL),
                        )
                    ]
                ),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def ocsp(
        self, leaf: x509.Certificate, *, revoked: bool = False, at: dt.datetime = NOW
    ) -> bytes:
        status = ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD
        response = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf,
                issuer=self.ca,
                algorithm=hashes.SHA256(),
                cert_status=status,
                this_update=at - dt.timedelta(minutes=5),
                next_update=at + dt.timedelta(hours=1),
                revocation_time=NOW - dt.timedelta(days=1) if revoked else None,
                revocation_reason=None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, self.ca)
            .sign(self.ca_key, hashes.SHA256())
        )
        return response.public_bytes(serialization.Encoding.DER)

    def tsa(self) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """A time-stamping unit issued by the CA (critical EKU timeStamping, RFC 3161)."""
        key = _key()
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name("TEST TSA"))
            .issuer_name(self.ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_usage(digital_signature=True), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.OCSP,
                            x509.UniformResourceIdentifier(OCSP_URL),
                        )
                    ]
                ),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )
        return cert, key

    def arl(self, *, revoke_ca: bool = False) -> bytes:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.root.subject)
            .last_update(NOW - dt.timedelta(hours=1))
            .next_update(NOW + dt.timedelta(days=7))
            .add_extension(x509.CRLNumber(1), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
                critical=False,
            )
        )
        if revoke_ca:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(self.ca.serial_number)
                .revocation_date(NOW - dt.timedelta(days=1))
                .build()
            )
        return builder.sign(self.root_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _ca(
    subject: x509.Name,
    key: rsa.RSAPrivateKey,
    issuer: x509.Name,
    issuer_key: rsa.RSAPrivateKey,
    path_length: int,
    crl: bool,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=30))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if crl:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier(CRL_URL)], None, None, None
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def build_pki() -> Pki:
    root_key, ca_key = _key(), _key()
    root = _ca(
        _name("TEST ECERNEP ROOT"), root_key, _name("TEST ECERNEP ROOT"), root_key, 2, crl=False
    )
    ca = _ca(_name("TEST ECEP CA Class 2"), ca_key, root.subject, root_key, 0, crl=True)
    store = TrustStore(
        [TrustedCertificate(root, "root", "TEST"), TrustedCertificate(ca, "intermediate", "TEST")]
    )
    return Pki(root, root_key, ca, ca_key, store)


def minimal_pdf(text: str = "Documento de prueba de berigna") -> bytes:
    """A valid one-page PDF built by hand (no dependencies)."""
    content = f"BT /F1 14 Tf 72 770 Td ({text}) Tj ET".encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
        b"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 "
        b"/BaseFont /Helvetica >> >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    ]
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    for number, body in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % number + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    )
    return out.getvalue()
