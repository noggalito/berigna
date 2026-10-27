# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Signer check before the PIN (RF-006): PR-VAL-02 to PR-VAL-05, PR-TOK-04."""

import datetime as dt
from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from berigna.core.errors import (
    CertificateExpiredError,
    CertificateRevokedError,
    CertificateValidationError,
    UntrustedCertificateError,
)
from berigna.core.trust import TrustedCertificate, TrustStore
from berigna.core.validation import check_signer

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
    ) -> x509.Certificate:
        key = _key()
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

    def ocsp(self, leaf: x509.Certificate, *, revoked: bool = False) -> bytes:
        status = ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD
        response = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf,
                issuer=self.ca,
                algorithm=hashes.SHA256(),
                cert_status=status,
                this_update=NOW - dt.timedelta(minutes=5),
                next_update=NOW + dt.timedelta(hours=1),
                revocation_time=NOW - dt.timedelta(days=1) if revoked else None,
                revocation_reason=None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, self.ca)
            .sign(self.ca_key, hashes.SHA256())
        )
        return response.public_bytes(serialization.Encoding.DER)

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


@pytest.fixture(scope="module")
def pki() -> Pki:
    root_key, ca_key = _key(), _key()
    root = _ca(
        _name("TEST ECERNEP ROOT"), root_key, _name("TEST ECERNEP ROOT"), root_key, 2, crl=False
    )
    ca = _ca(_name("TEST ECEP CA Class 2"), ca_key, root.subject, root_key, 0, crl=True)
    store = TrustStore(
        [TrustedCertificate(root, "root", "TEST"), TrustedCertificate(ca, "intermediate", "TEST")]
    )
    return Pki(root, root_key, ca, ca_key, store)


def test_valid_certificate_with_fresh_ocsp(pki: Pki) -> None:
    leaf = pki.leaf("FIRMANTE VALIDO")
    result = check_signer(
        leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
    )
    assert result.revocation_checked
    assert not result.only_basic_level
    assert [c.subject for c in result.chain] == [pki.root.subject, pki.ca.subject, leaf.subject]


def test_revoked_certificate_is_rejected(pki: Pki) -> None:
    leaf = pki.leaf("FIRMANTE REVOCADO")
    with pytest.raises(CertificateRevokedError):
        check_signer(
            leaf,
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf, revoked=True)],
            crls=[pki.arl()],
        )


def test_revoked_intermediate_is_rejected(pki: Pki) -> None:
    leaf = pki.leaf("FIRMANTE CON CA REVOCADA")
    with pytest.raises(CertificateRevokedError):
        check_signer(
            leaf,
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],
            crls=[pki.arl(revoke_ca=True)],
        )


@pytest.mark.parametrize("days", [(-400, -10), (5, 400)], ids=["caducado", "aun-no-valido"])
def test_certificate_outside_its_validity_is_rejected(pki: Pki, days: tuple[int, int]) -> None:
    leaf = pki.leaf("FIRMANTE FUERA DE VIGENCIA", days=days)
    with pytest.raises(CertificateExpiredError):
        check_signer(
            leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
        )


def test_certificate_outside_the_iofe_is_rejected(pki: Pki) -> None:
    other_root_only = TrustStore([TrustedCertificate(pki.ca, "intermediate", "TEST")])
    leaf = pki.leaf("FIRMANTE SIN RAIZ")
    with pytest.raises(UntrustedCertificateError):
        check_signer(
            leaf, other_root_only, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
        )


def test_certificate_without_non_repudiation_is_rejected(pki: Pki) -> None:
    leaf = pki.leaf("CERTIFICADO DE AUTENTICACION", non_repudiation=False)
    with pytest.raises(CertificateValidationError):
        check_signer(
            leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
        )


def test_without_revocation_data_only_basic_level_is_allowed(pki: Pki) -> None:
    """RF-006 (2): no network -> not a rejection, but B-B only with a warning."""
    leaf = pki.leaf("FIRMANTE SIN RED")
    result = check_signer(leaf, pki.store, online=False)
    assert not result.revocation_checked
    assert result.only_basic_level
    assert result.chain[-1] == leaf


def test_expired_certificate_is_rejected_even_without_revocation_data(pki: Pki) -> None:
    leaf = pki.leaf("CADUCADO SIN RED", days=(-400, -10))
    with pytest.raises(CertificateExpiredError):
        check_signer(leaf, pki.store, online=False)


def test_online_mode_uses_requests_fetchers_with_timeout() -> None:
    from berigna.core.validation.preflight import _requests_fetchers

    fetchers = _requests_fetchers(3.0)
    assert fetchers.ocsp_fetcher is not None
    assert fetchers.crl_fetcher is not None
