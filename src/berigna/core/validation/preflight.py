# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
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

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
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
from pyhanko_certvalidator.fetchers.api import Fetchers
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)

from berigna.core.errors import (
    CertificateExpiredError,
    CertificateRevokedError,
    CertificateValidationError,
    UntrustedCertificateError,
)
from berigna.core.trust import TrustStore

_SIGNING_POLICY = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.OCSP_REQUIRED,
    intermediate_ca_cert_rule=RevocationCheckingRule.CRL_REQUIRED,
)
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


def _requests_fetchers(timeout: float) -> Fetchers:
    backend = RequestsFetcherBackend(per_request_timeout=timeout)  # type: ignore[no-untyped-call]
    return backend.get_fetchers()


def _to_asn1(certificate: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))


def _to_cryptography(certificate: asn1_x509.Certificate) -> x509.Certificate:
    return x509.load_der_x509_certificate(certificate.dump())


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
    leaf = _to_asn1(certificate)
    roots = [_to_asn1(c) for c in store.roots]
    others = [_to_asn1(c) for c in store.intermediates]

    def run(policy: RevocationCheckingPolicy) -> ValidationPath:
        context = ValidationContext(
            trust_roots=roots,
            other_certs=others,
            moment=when,
            allow_fetching=online,
            crls=list(crls),
            ocsps=list(ocsp_responses),
            revinfo_policy=CertRevTrustPolicy(policy),
            fetchers=_requests_fetchers(timeout) if online else None,
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

    chain = tuple(_to_cryptography(c) for c in path.iter_certs(include_root=True))
    return SignerCheck(
        revocation_checked=note is None, chain=chain, moment=when, revocation_note=note
    )
