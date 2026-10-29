# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Check of the signer certificate before asking for the PIN (RF-006, ACR-13 to ACR-15).

Validity, chain up to an IOFE anchor (ADR-0009), non-repudiation usage and revocation:

- end-entity certificate: OCSP only. The CRL of the DNIe issuing CA is ~109 MB and is never
  used when signing (RF-063).
- intermediate CAs: CRL (their ARLs are a few hundred bytes).

If revocation cannot be established (no network, responder down, out-of-date data) the certificate
is still checked offline and the caller may only offer a B-B signature, with a warning
(RF-006, 2); :class:`RevocationNote` says why. Any other failure rejects the certificate.

:func:`check_signer` runs its own asyncio event loop: call it from a worker thread, never from
inside a running loop (arquitectura-general §5).
"""

import asyncio
import datetime as dt
import enum
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import (
    ExpiredError,
    InsufficientRevinfoError,
    InvalidCertificateError,
    NotYetValidError,
    PathBuildingError,
    PathValidationError,
    RevokedError,
    ValidationError,
)
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)

from berigna.core.certs import to_asn1, to_cryptography
from berigna.core.errors import (
    CertificateExpiredError,
    CertificateRevokedError,
    CertificateValidationError,
    UntrustedCertificateError,
)
from berigna.core.net.fetchers import revocation_fetchers
from berigna.core.trust import TrustStore
from berigna.core.validation.algorithms import MIN_RSA_BITS, algorithm_policy

_SIGNING_POLICY = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.OCSP_REQUIRED,
    intermediate_ca_cert_rule=RevocationCheckingRule.CRL_REQUIRED,
)
# Validating "now" fixes the moment before the OCSP and CRL services answer, and their answers
# are dated when they are produced: with pyhanko-certvalidator's default tolerance (1 s) a
# response that took two seconds was "too recent" and the signer was left unchecked. The
# services can take up to a minute (R-17: 20 s to connect, a retry, mirrors).
CURRENT_TIME_TOLERANCE = dt.timedelta(minutes=5)
# Validation at a given moment in the past keeps the strict default.
POINT_IN_TIME_TOLERANCE = dt.timedelta(seconds=1)


def time_tolerance(moment: dt.datetime | None) -> dt.timedelta:
    """Tolerance for revocation data when validating at ``moment`` (``None``: now)."""
    return CURRENT_TIME_TOLERANCE if moment is None else POINT_IN_TIME_TOLERANCE


_OFFLINE_POLICY = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.NO_CHECK,
    intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK,
)


class RevocationNote(enum.Enum):
    """Why revocation could not be established; the UI picks the warning from it.

    pyhanko-certvalidator 0.26.3 reports out-of-date OCSP data under a mandatory rule with the
    same error as missing data, so an expired response counts as ``UNAVAILABLE`` (or
    ``OFFLINE``); telling them apart would mean parsing its messages.
    """

    OFFLINE = "offline"  # network use disabled by the user or the caller
    UNAVAILABLE = "unavailable"  # online, but no usable OCSP/CRL (network, responder, old data)


@dataclass(frozen=True)
class SignerCheck:
    """Outcome of a successful check. ``revocation_checked`` False means: B-B only."""

    revocation_checked: bool
    chain: tuple[x509.Certificate, ...]  # trust anchor first, signer certificate last
    moment: dt.datetime
    revocation_note: RevocationNote | None = None  # set only when revocation_checked is False

    @property
    def only_basic_level(self) -> bool:
        return not self.revocation_checked


def signing_validation_context(
    store: TrustStore,
    *,
    moment: dt.datetime | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    timeout: float = 10.0,
    policy: RevocationCheckingPolicy = _SIGNING_POLICY,
    tolerance: dt.timedelta | None = None,
) -> ValidationContext:
    """Validation context with the signing rules: OCSP for end-entity certificates, CRLs for
    CAs, anchors of ``store``. Also used to gather the data embedded in a B-LT signature.

    ``tolerance`` defaults to :func:`time_tolerance` of ``moment``.
    """
    return ValidationContext(
        trust_roots=[to_asn1(c) for c in store.roots],
        other_certs=[to_asn1(c) for c in store.intermediates],
        moment=moment,
        time_tolerance=time_tolerance(moment) if tolerance is None else tolerance,
        allow_fetching=online,
        crls=list(crls),
        ocsps=list(ocsp_responses),
        revinfo_policy=CertRevTrustPolicy(policy),
        algorithm_usage_policy=algorithm_policy(),
        fetchers=revocation_fetchers(timeout) if online else None,
    )


def _check_key_size(certificate: x509.Certificate) -> None:
    """The signer's own key (ACR-18): the chain policy only judges the keys that sign others."""
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < MIN_RSA_BITS:
        raise CertificateValidationError(
            f"RSA key of {key.key_size} bits; at least {MIN_RSA_BITS} are required"
        )


def check_signer(
    certificate: x509.Certificate,
    store: TrustStore,
    *,
    moment: dt.datetime | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    timeout: float = 10.0,
) -> SignerCheck:
    """Validate ``certificate`` for signing at ``moment`` (now by default).

    Raises a :class:`~berigna.core.errors.SignerCertificateError` subclass when the
    certificate must not be used. ``ocsp_responses`` and ``crls`` let callers (and tests)
    supply revocation data; with ``online`` they are fetched from the URLs in the chain.
    """
    when = moment or dt.datetime.now(dt.UTC)
    _check_key_size(certificate)
    leaf = to_asn1(certificate)

    def run(policy: RevocationCheckingPolicy) -> ValidationPath:
        context = signing_validation_context(
            store,
            moment=when,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
            timeout=timeout,
            policy=policy,
            tolerance=time_tolerance(moment),  # ``when`` is fixed, but it may still be "now"
        )
        validator = CertificateValidator(leaf, validation_context=context)
        usage = validator.async_validate_usage({"non_repudiation"})  # type: ignore[no-untyped-call]
        return cast(ValidationPath, asyncio.run(usage))

    note: RevocationNote | None = None
    try:
        try:
            path = run(_SIGNING_POLICY)
        except InsufficientRevinfoError:
            note = RevocationNote.UNAVAILABLE if online else RevocationNote.OFFLINE
            path = run(_OFFLINE_POLICY)
    except RevokedError as exc:
        raise CertificateRevokedError(str(exc)) from exc
    except (ExpiredError, NotYetValidError) as exc:
        raise CertificateExpiredError(str(exc)) from exc
    except PathBuildingError as exc:
        raise UntrustedCertificateError(str(exc)) from exc
    except (InvalidCertificateError, PathValidationError, ValidationError) as exc:
        raise CertificateValidationError(str(exc)) from exc

    chain = tuple(to_cryptography(c) for c in path.iter_certs(include_root=True))
    return SignerCheck(
        revocation_checked=note is None, chain=chain, moment=when, revocation_note=note
    )
