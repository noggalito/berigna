# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Trust in the time-stamping authority before its time-stamp is written (R-DES-20).

:func:`core.net.tsa.check_token` (R-DES-07) catches answers damaged on the way, not a token
signed with somebody else's certificate by whoever sits on the plain HTTP of the TSA. Here
the TSA certificate itself is validated against the trust store, as the verifier will:

- :func:`check_tsa`: chain to an anchor of the store (the IOFE and, through ADR-0022, every
  CA accredited in the TSL of INDECOPI), time-stamping usage, validity and revocation;
- :class:`TrustedTimeStamper`: every token of a time-stamper goes through it before it is
  used, once per TSA certificate;
- :func:`probe_trusted`: the TSA answers and is trusted, which the step before the PIN,
  "Test" in Preferences and the diagnosis say alike.
"""

import asyncio
import datetime as dt
import logging
import threading
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from asn1crypto import cms
from asn1crypto import x509 as asn1_x509
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.generic_cms import extract_certs_for_validation
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
from pyhanko_certvalidator.policy_decl import RevocationCheckingPolicy, RevocationCheckingRule

from berigna.core.errors import UNREADABLE_DATA, BerignaError, TsaError, UntrustedTsaError
from berigna.core.net.tsa import PROBE_DIGEST, probe, token_certificates
from berigna.core.trust import TrustStore
from berigna.core.validation.preflight import (
    _OFFLINE_POLICY,
    signing_validation_context,
    time_tolerance,
)

log = logging.getLogger(__name__)

# OCSP or CRL for the TSA certificate: unlike the DNIe's (109 MB, OCSP only), a TSA may
# publish only a CRL. berigna never downloads the CRL of an end-entity certificate
# (core.net.fetchers): with only a CRL, the revocation of the TSA is checked when the CRL is
# supplied, and otherwise it cannot be established (review of R-DES-20).
_TSA_POLICY = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
    intermediate_ca_cert_rule=RevocationCheckingRule.CRL_REQUIRED,
)
# What the check before the PIN may take, as the probe (core.net.tsa.probe): the revocation
# services of the TSA can hang on a broken IPv6 route as the TSA itself.
CHECK_DEADLINE = 30.0
_UNREADABLE_TOKEN: tuple[type[Exception], ...] = (*UNREADABLE_DATA, SignatureValidationError)


async def check_tsa(
    certificate: asn1_x509.Certificate,
    store: TrustStore,
    *,
    intermediates: Sequence[asn1_x509.Certificate] = (),
    moment: dt.datetime | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    timeout: float = 10.0,
) -> None:
    """Raise :class:`~berigna.core.errors.UntrustedTsaError` unless the TSA ``certificate``
    (with the ``intermediates`` its token carries) can stamp signatures now.

    The chain must reach an anchor of ``store``, the certificate must be valid and for
    time-stamping, and it must not be revoked. Revocation that cannot be established does not
    stop the time-stamp (decision of 2026-11-08): it goes to the technical log, and a B-LT
    that needs it keeps falling back to B-T with its note. Damaged revocation data from the
    network is the same case, as for the signer (R-DES-07). A coroutine: pyHanko asks for the
    time-stamp inside its own event loop.
    """
    when = moment or dt.datetime.now(dt.UTC)

    async def run(policy: RevocationCheckingPolicy, online: bool = online) -> None:
        context = signing_validation_context(
            store,
            moment=when,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
            timeout=timeout,
            policy=policy,
            tolerance=time_tolerance(moment),
        )
        validator = CertificateValidator(
            certificate, intermediate_certs=list(intermediates), validation_context=context
        )
        await validator.async_validate_usage(set(), {"time_stamping"})  # type: ignore[no-untyped-call]

    try:
        try:
            await run(_TSA_POLICY)
        except InsufficientRevinfoError as exc:
            # offline it is expected; online it is worth knowing (RF-083)
            log.log(
                logging.WARNING if online else logging.DEBUG,
                "revocation of the TSA certificate not established: %s",
                exc,
            )
            await run(_OFFLINE_POLICY)
        except UNREADABLE_DATA:
            if not online:
                raise
            log.warning("revocation data of the TSA could not be processed", exc_info=True)
            await run(_OFFLINE_POLICY, online=False)
    except RevokedError as exc:
        raise UntrustedTsaError(f"the TSA certificate is revoked: {exc}") from exc
    except (
        ExpiredError,
        NotYetValidError,
        PathBuildingError,
        InvalidCertificateError,
        PathValidationError,
        ValidationError,
    ) as exc:
        raise UntrustedTsaError(f"the TSA is not trusted: {exc}") from exc
    except UNREADABLE_DATA as exc:
        log.warning("the TSA certificate could not be validated", exc_info=True)
        raise UntrustedTsaError(f"the TSA certificate cannot be validated: {exc}") from exc


class TrustedTimeStamper(TimeStamper):
    """``inner``, whose every token is checked by ``check`` before it is used: the test
    token before the PIN (:meth:`check_now`), and each real one before it is written into
    the signature. Each TSA certificate is validated once.

    pyHanko asks a time-stamper for tokens (``async_timestamp``, ``async_dummy_response``)
    and, for B-LT, for the validation paths of its certificates: all three go to ``inner``.
    """

    def __init__(
        self,
        inner: TimeStamper,
        check: Callable[[asn1_x509.Certificate, list[asn1_x509.Certificate]], Awaitable[None]],
    ) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self._inner = inner
        self._check = check
        self._trusted: set[bytes] = set()

    async def _checked(self, token: cms.ContentInfo) -> cms.ContentInfo:
        try:
            signed_data = token["content"]
            certificate = extract_certs_for_validation(signed_data).signer_cert
            others = token_certificates(signed_data)
        except _UNREADABLE_TOKEN as exc:
            # a TSA that ignored cert_req, or a token that cannot be read: not a valid one
            raise TsaError(
                f"the time-stamp token does not carry its TSA certificate: {exc}"
            ) from exc
        if certificate.dump() not in self._trusted:
            await self._check(certificate, others)
            self._trusted.add(certificate.dump())
        return token

    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> cms.ContentInfo:
        return await self._checked(await self._inner.async_timestamp(message_digest, md_algorithm))

    async def async_dummy_response(self, md_algorithm: str) -> cms.ContentInfo:
        return await self._checked(await self._inner.async_dummy_response(md_algorithm))

    def validation_paths(self, validation_context: ValidationContext) -> Any:
        return self._inner.validation_paths(validation_context)  # type: ignore[no-untyped-call]

    def check_now(self, md_algorithm: str = PROBE_DIGEST, deadline: float = CHECK_DEADLINE) -> None:
        """The TSA of the test token (already fetched by :func:`probe`), before the PIN,
        within ``deadline`` (in a daemon thread, as the probe)."""
        outcome: list[BaseException | None] = []

        def run() -> None:
            try:
                asyncio.run(self.async_dummy_response(md_algorithm))
                outcome.append(None)
            except Exception as exc:  # re-raised below in the calling thread
                outcome.append(exc)

        worker = threading.Thread(target=run, name="berigna-tsa-check", daemon=True)
        worker.start()
        worker.join(deadline)
        if not outcome:
            raise TsaError(f"the TSA could not be checked within {deadline:g} s")
        error = outcome[0]
        if isinstance(error, BerignaError):
            raise error
        if error is not None:
            raise TsaError(f"the TSA could not be checked: {error}") from error


def trusted_time_stamper(
    timestamper: TimeStamper,
    store: TrustStore,
    *,
    online: bool,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> TrustedTimeStamper:
    """``timestamper``, with its TSA validated against ``store``."""

    async def check(
        certificate: asn1_x509.Certificate, others: list[asn1_x509.Certificate]
    ) -> None:
        await check_tsa(
            certificate,
            store,
            intermediates=others,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
        )

    return TrustedTimeStamper(timestamper, check)


def probe_trusted(
    timestamper: TimeStamper,
    store: TrustStore,
    *,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> TrustedTimeStamper:
    """The TSA answers with a valid token (:func:`probe`, TsaError) and is trusted
    (UntrustedTsaError). Returns the time-stamper to sign with."""
    probe(timestamper)
    trusted = trusted_time_stamper(
        timestamper, store, online=online, ocsp_responses=ocsp_responses, crls=crls
    )
    trusted.check_now()
    return trusted
