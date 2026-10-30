# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""What the signature formats share: the baseline levels and the signer that lets the token
make the private-key operation (RNF-SEG-01)."""

import enum
import hashlib
from collections.abc import Sequence

from asn1crypto import algos
from cryptography import x509
from pyhanko.sign import signers
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko_certvalidator.errors import (
    CRLValidationError,
    OCSPValidationError,
    PathError,
    ValidationError,
)
from pyhanko_certvalidator.registry import SimpleCertificateStore

from berigna.core.certs import to_asn1
from berigna.core.token.base import HashAlgorithmName, TokenSigner

SIGNATURE_SIZE = 256  # RSA-2048 (DNIe v2, SPK-01)


class SignatureLevel(enum.Enum):
    """Baseline levels of ETSI EN 319 142-1 (PAdES), 319 122-1 (CAdES) and 319 132-1 (XAdES)."""

    B_B = "B-B"
    B_T = "B-T"
    B_LT = "B-LT"
    B_LTA = "B-LTA"


# Failures of a validation service after the card has signed: they lower the level reached,
# they do not lose the signature.
VALIDATION_SERVICE_ERRORS: tuple[type[Exception], ...] = (
    ValidationError,
    PathError,  # a path that cannot be built, or an intermediate that cannot be fetched
    CRLValidationError,
    OCSPValidationError,
    SignatureValidationError,
    ValueError,
)


def registry(certificates: Sequence[x509.Certificate]) -> SimpleCertificateStore:
    store = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    for certificate in certificates:
        store.register(to_asn1(certificate))
    return store


def required[T](value: T | None, level: SignatureLevel, what: str) -> T:
    if value is None:
        raise ValueError(f"{level.value} needs {what}")
    return value


class TokenCmsSigner(signers.Signer):
    """pyHanko signer that hashes locally and lets the token sign the digest (RNF-SEG-01).

    ``chain`` goes from the trust anchor to the signer certificate; the anchor is not embedded.
    """

    def __init__(
        self,
        token: TokenSigner,
        chain: Sequence[x509.Certificate],
        digest: HashAlgorithmName,
    ) -> None:
        super().__init__(
            signing_cert=to_asn1(chain[-1]),
            cert_registry=registry(chain[:-1]),
            signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": f"{digest}_rsa"}),
            embed_roots=False,
        )
        self._token = token
        self._digest: HashAlgorithmName = digest

    async def async_sign_raw(
        self, data: bytes, digest_algorithm: str, dry_run: bool = False
    ) -> bytes:
        if dry_run:
            return bytes(SIGNATURE_SIZE)
        if digest_algorithm != self._digest:
            raise ValueError(f"unexpected digest algorithm {digest_algorithm!r}")
        return self._token.sign_digest(hashlib.new(digest_algorithm, data).digest(), self._digest)
