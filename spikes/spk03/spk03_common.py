# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Prototipo de investigación (spike). No es código de producción.
"""SPK-03 shared helpers: token-like signer (digest in, signature out) and local test TSA."""
import hashlib
from pathlib import Path

from asn1crypto import keys, x509 as ax509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko.sign.signers.pdf_cms import Signer
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
from asn1crypto.algos import SignedDigestAlgorithm


def load_cert(path: Path) -> ax509.Certificate:
    from asn1crypto import pem
    _, _, der = pem.unarmor(path.read_bytes())
    return ax509.Certificate.load(der)


class TokenLike:
    """Imitates the DNIe v2 PSO:CDS contract: receives a SHA-256 digest, returns a PKCS#1 v1.5 signature."""

    def __init__(self, key_der: bytes):
        self._key = serialization.load_der_private_key(key_der, password=None)
        self.calls = 0

    def sign_digest(self, digest: bytes) -> bytes:
        assert len(digest) == 32
        self.calls += 1
        return self._key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


class TokenSigner(Signer):
    """pyHanko Signer delegating the private-key operation to a TokenLike (as berigna will do with the DNIe)."""

    def __init__(self, token: TokenLike, signing_cert, chain):
        super().__init__(signing_cert=signing_cert,
                         cert_registry=SimpleCertificateStore.from_certs(chain),
                         signature_mechanism=SignedDigestAlgorithm({"algorithm": "sha256_rsa"}))
        self.token = token

    async def async_sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) -> bytes:
        if dry_run:
            return bytes(256)
        assert digest_algorithm == "sha256"
        return self.token.sign_digest(hashlib.sha256(data).digest())


def test_tsa(pki: Path) -> DummyTimeStamper:
    tsa_cert = load_cert(pki / "tsa.pem")
    root = load_cert(pki / "root.pem")
    return DummyTimeStamper(tsa_cert=tsa_cert,
                            tsa_key=keys.PrivateKeyInfo.load((pki / "tsa.key.der").read_bytes()),
                            certs_to_embed=SimpleCertificateStore.from_certs([root]))
