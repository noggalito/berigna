# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Cryptographic algorithms berigna refuses (ACR-18; INDECOPI guide, requirement 6 and annex 1).

The values are written here instead of relying on the defaults of pyhanko-certvalidator, so
that an update of the library cannot relax them silently. They apply to certificate chains,
signatures and time-stamps, both in the signer check and in verification.
"""

from pyhanko.sign.validation.utils import CMSAlgorithmUsagePolicy
from pyhanko_certvalidator.policy_decl import DisallowWeakAlgorithmsPolicy

WEAK_DIGESTS = frozenset({"md2", "md5", "sha1"})
MIN_RSA_BITS = 2048


def algorithm_policy() -> DisallowWeakAlgorithmsPolicy:
    """Policy for certificate chains and revocation data."""
    return DisallowWeakAlgorithmsPolicy(  # type: ignore[no-untyped-call]
        weak_hash_algos=WEAK_DIGESTS, rsa_key_size_threshold=MIN_RSA_BITS
    )


def signature_algorithm_policy() -> CMSAlgorithmUsagePolicy:
    """The same policy, for CMS signatures and time-stamp tokens."""
    return CMSAlgorithmUsagePolicy.lift_policy(algorithm_policy())
