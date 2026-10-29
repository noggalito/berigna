# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Obsolete algorithms are refused by berigna's own policy, not a library default (ACR-18)."""

import pytest
from asn1crypto import algos
from cryptography.hazmat.primitives.asymmetric import rsa

from berigna.core.errors import CertificateValidationError
from berigna.core.validation import check_signer
from berigna.core.validation.algorithms import (
    MIN_RSA_BITS,
    WEAK_DIGESTS,
    algorithm_policy,
    signature_algorithm_policy,
)
from support.pki import Pki, build_pki


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def test_policy_values() -> None:
    assert {"md2", "md5", "sha1"} == WEAK_DIGESTS
    assert MIN_RSA_BITS == 2048
    policy = algorithm_policy()
    assert policy.weak_hash_algos == WEAK_DIGESTS
    assert policy.rsa_key_size_threshold == MIN_RSA_BITS
    for name in WEAK_DIGESTS:
        digest = algos.DigestAlgorithm({"algorithm": name})
        assert not signature_algorithm_policy().digest_algorithm_allowed(digest, None).allowed
    sha256 = algos.DigestAlgorithm({"algorithm": "sha256"})
    assert signature_algorithm_policy().digest_algorithm_allowed(sha256, None).allowed


def test_signer_check_refuses_a_short_rsa_key(pki: Pki) -> None:
    """The signer check applies the same policy: a 1024-bit certificate is never used."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - on purpose
    leaf = pki.leaf("FIRMANTE RSA1024", key=key)
    with pytest.raises(CertificateValidationError, match="1024 bits"):
        check_signer(
            leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
        )
