# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Trust in the time-stamping authority before its time-stamp is written (R-DES-20).

:func:`core.net.tsa.check_token` (R-DES-07) catches answers damaged on the way, not a token
signed with somebody else's certificate by whoever sits on the plain HTTP of the TSA. Here
the TSA certificate itself is validated against the trust store, as the verifier will:

- :func:`check_tsa`: chain to an anchor of the store (the IOFE and, through ADR-0022, every
  CA accredited in the TSL of INDECOPI), time-stamping usage, validity and revocation;
- :class:`TrustedTimeStamper`: every token of a time-stamper goes through it before it is
  used, once per TSA certificate, and within a deadline before the PIN;
- :func:`probe_trusted`: the TSA answers and is trusted, which the step before the PIN,
  "Test" in Preferences and the diagnosis say alike.
"""

import asyncio
import datetime as dt
import logging
import threading
import time
from collections.abc import Sequence
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
MIN_CHECK_TIME = 5.0  # left to the trust check when the probe took almost all of it
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
    """``inner``, whose every token goes through :func:`check_tsa` against ``store`` before it
    is used: the test token before the PIN (:meth:`check_now`), and each real one before it
    is written into the signature. Each TSA certificate is validated once.

    pyHanko asks a time-stamper for tokens (``async_timestamp``, ``async_dummy_response``)
    and, for B-LT, for the validation paths of its certificates: all three go to ``inner``.
    """

    def __init__(
        self,
        inner: TimeStamper,
        store: TrustStore,
        *,
        online: bool,
        ocsp_responses: Sequence[bytes] = (),
        crls: Sequence[bytes] = (),
    ) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self._inner = inner
        self._store = store
        self._online = online
        self._ocsp_responses = ocsp_responses
        self._crls = crls
        self._trusted: set[bytes] = set()  # DER of the TSA certificates already validated

    @staticmethod
    def _certificates(
        token: cms.ContentInfo,
    ) -> tuple[asn1_x509.Certificate, list[asn1_x509.Certificate]]:
        try:
            signed_data = token["content"]
            return extract_certs_for_validation(signed_data).signer_cert, token_certificates(
                signed_data
            )
        except _UNREADABLE_TOKEN as exc:
            # a TSA that ignored cert_req, or a token that cannot be read: not a valid one
            raise TsaError(
                f"the time-stamp token does not carry its TSA certificate: {exc}"
            ) from exc

    async def _check(self, token: cms.ContentInfo, *, online: bool) -> None:
        certificate, others = self._certificates(token)
        if certificate.dump() in self._trusted:
            return
        await check_tsa(
            certificate,
            self._store,
            intermediates=others,
            online=online,
            ocsp_responses=self._ocsp_responses,
            crls=self._crls,
        )
        self._trusted.add(certificate.dump())

    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> cms.ContentInfo:
        """A real time-stamp, after the PIN. Its TSA certificate was validated before the PIN
        (:meth:`check_now`); another one (a TSA that renewed it, or several units) is
        validated without the network, so that signing never hangs once the card has signed:
        its revocation counts only with the data given (decision of 2026-11-08)."""
        token: cms.ContentInfo = await self._inner.async_timestamp(message_digest, md_algorithm)
        await self._check(token, online=False)
        return token

    async def async_dummy_response(self, md_algorithm: str) -> cms.ContentInfo:
        token: cms.ContentInfo = await self._inner.async_dummy_response(md_algorithm)
        await self._check(token, online=False)
        return token

    def validation_paths(self, validation_context: ValidationContext) -> Any:
        return self._inner.validation_paths(validation_context)  # type: ignore[no-untyped-call]

    def check_now(self, md_algorithm: str = PROBE_DIGEST, deadline: float = CHECK_DEADLINE) -> None:
        """Validate the TSA of the test token before the PIN, with the network if allowed.

        The test token is the one :func:`probe` left (pyHanko keeps it). Only the online
        validation runs in a daemon thread, which touches nothing of this object, within
        ``deadline``: the revocation services of the TSA may hang. Past it, revocation counts
        as not established (decision of 2026-11-08) and the rest is validated without the
        network: a TSA whose chain does not hold is still refused (ERR-314)."""
        try:
            token = asyncio.run(self._inner.async_dummy_response(md_algorithm))
            certificate, others = self._certificates(token)
            if certificate.dump() in self._trusted:
                return
            if self._online and not self._validated_online(certificate, others, deadline):
                log.warning(
                    "revocation of the TSA not established within %g s: its chain is "
                    "checked offline",
                    deadline,
                )
                asyncio.run(self._check(token, online=False))
            elif not self._online:
                asyncio.run(self._check(token, online=False))
            self._trusted.add(certificate.dump())
        except BerignaError:
            raise
        except Exception as exc:  # anything else: the TSA could not be checked, not ERR-000
            raise TsaError(f"the TSA could not be checked: {exc}") from exc

    def _validated_online(
        self,
        certificate: asn1_x509.Certificate,
        others: list[asn1_x509.Certificate],
        deadline: float,
    ) -> bool:
        """Whether the online validation finished within ``deadline`` (and passed: if it
        failed, its error is raised)."""
        outcome: list[BaseException | None] = []

        def run() -> None:
            try:
                asyncio.run(
                    check_tsa(
                        certificate,
                        self._store,
                        intermediates=others,
                        online=True,
                        ocsp_responses=self._ocsp_responses,
                        crls=self._crls,
                    )
                )
                outcome.append(None)
            except Exception as exc:  # re-raised below in the calling thread
                outcome.append(exc)

        worker = threading.Thread(target=run, name="berigna-tsa-check", daemon=True)
        worker.start()
        worker.join(deadline)
        if not outcome:
            return False
        if outcome[0] is not None:
            raise outcome[0]
        return True


def probe_trusted(
    timestamper: TimeStamper,
    store: TrustStore,
    *,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    deadline: float = CHECK_DEADLINE,
) -> TrustedTimeStamper:
    """The TSA answers with a valid token (:func:`probe`, TsaError) and is trusted
    (UntrustedTsaError), both within ``deadline`` (plus at most ``MIN_CHECK_TIME`` when the
    probe took almost all of it): the step before the PIN, "Test" in Preferences and the
    diagnosis wait about as long as the probe alone did. Returns the time-stamper to sign
    with."""
    start = time.monotonic()
    probe(timestamper, deadline=deadline)
    trusted = TrustedTimeStamper(
        timestamper, store, online=online, ocsp_responses=ocsp_responses, crls=crls
    )
    remaining = deadline - (time.monotonic() - start)
    trusted.check_now(deadline=max(remaining, MIN_CHECK_TIME))
    return trusted
