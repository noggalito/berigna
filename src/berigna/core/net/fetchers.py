# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Fetchers of revocation data shared by the signer check, signing and verification.

Two rules apply everywhere berigna goes online for OCSP or CRLs:

- the CRL of an end-entity certificate is never downloaded: for the DNIe it weighs ~109 MB
  (RF-063). End-entity certificates are checked with OCSP; CRLs are fetched for CAs only.
- a failed request is retried once after a short pause. RENIEC's services have failed the
  first request after a while without use and answered the next one in ~1 s (R-17).

CRLs are downloaded here and not with pyhanko-certvalidator 0.26.3's client, which has two
faults that turned a slow mirror into a failed check (2026-10-27): it raises if any distribution
point fails even when another one answered (``crl_job_results_as_completed`` never records a
success), and it caches failed downloads, so a retry repeats the failure. RENIEC publishes each
CA's CRL on two mirrors; ``crl2.reniec.gob.pe`` takes ~15 s to answer the first request after a
while without use. Here every distribution point is tried at once and the first CRL that
arrives is used (mirrors publish the same CRL). Each download runs in a daemon thread of its
own: the slow mirror is not waited for, neither by the check nor when the event loop or the
application exits (``asyncio.to_thread`` workers would hold both).

The delays come from TCP connection set-up: RENIEC's network drops connection attempts
intermittently (measured: connections to ``crl2`` that take 12.6 or 15.25 s, the times of the
third and fourth SYN retransmission, and OCSP connections that time out at 15 s). Hence:

- mirrors are hedged, not raced: the next distribution point is only tried if the previous one
  has not answered within :data:`HEDGE_DELAY`, so the usual case opens a single connection;
- the connection time-out (:data:`CONNECT_TIMEOUT`) is separate from the read time-out and
  long enough to wait for the retransmission at 15 s: a slow answer instead of a failed check;
- an OCSP request whose connection timed out after that wait is not retried: the responder has
  been seen refusing connections for longer than that, and the retry only doubled the wait.
"""

import asyncio
import functools
import threading
from collections.abc import Callable, Iterable
from typing import Any

import requests
from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import pem
from asn1crypto import x509 as asn1_x509
from pyhanko_certvalidator.errors import CRLFetchError, OCSPFetchError
from pyhanko_certvalidator.fetchers.api import (
    CRLFetcher,
    FetcherBackend,
    Fetchers,
    OCSPFetcher,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
from pyhanko_certvalidator.util import get_relevant_crl_dps, issuer_serial

RETRY_PAUSE = 0.5  # seconds
HEDGE_DELAY = 2.0  # seconds before trying the next CRL mirror
CONNECT_TIMEOUT = 20.0  # seconds; covers the SYN retransmission at 15 s

Timeouts = tuple[float, float]  # (connect, read), as requests takes them


def _download_crl(url: str, timeouts: Timeouts) -> asn1_crl.CertificateList:
    try:
        response = requests.get(url, timeout=timeouts, headers={"Accept": "application/pkix-crl"})
        if response.status_code != 200:
            raise CRLFetchError(f"{url}: HTTP {response.status_code}")
        data = response.content
        if pem.detect(data):
            _, _, data = pem.unarmor(data)
        return asn1_crl.CertificateList.load(data)
    except (OSError, ValueError) as exc:
        raise CRLFetchError(f"cannot fetch the CRL at {url}: {exc}") from exc


def _in_daemon_thread(
    work: Callable[[], asn1_crl.CertificateList],
) -> asyncio.Future[asn1_crl.CertificateList]:
    loop = asyncio.get_running_loop()
    future: asyncio.Future[asn1_crl.CertificateList] = loop.create_future()

    def deliver(outcome: Any, failed: bool) -> None:
        if future.done():  # cancelled: the check moved on
            return
        if failed:
            future.set_exception(outcome)
        else:
            future.set_result(outcome)

    def run() -> None:
        try:
            outcome, failed = work(), False
        except CRLFetchError as exc:
            outcome, failed = exc, True
        if not loop.is_closed():
            loop.call_soon_threadsafe(deliver, outcome, failed)

    threading.Thread(target=run, name="berigna-crl", daemon=True).start()
    return future


class CaOnlyCrlFetcher(CRLFetcher):
    """CRLs of CA certificates only, hedged over the mirrors, one retry if none answers."""

    def __init__(
        self,
        timeouts: Timeouts,
        pause: float = RETRY_PAUSE,
        hedge: float = HEDGE_DELAY,
        download: Callable[[str, Timeouts], asn1_crl.CertificateList] = _download_crl,
    ) -> None:
        self._timeouts = timeouts
        self._pause = pause
        self._hedge = hedge
        self._download = download
        self._by_cert: dict[Any, list[asn1_crl.CertificateList]] = {}

    async def _first(self, urls: list[str]) -> asn1_crl.CertificateList:
        """First CRL obtained; the next mirror starts after the hedge delay or a failure."""
        failures: list[CRLFetchError] = []
        pending: set[asyncio.Future[asn1_crl.CertificateList]] = set()
        for index, url in enumerate(urls):
            pending.add(_in_daemon_thread(functools.partial(self._download, url, self._timeouts)))
            last = index == len(urls) - 1
            while pending:
                done, pending = await asyncio.wait(
                    pending,
                    timeout=None if last else self._hedge,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for finished in done:
                    try:
                        return finished.result()
                    except CRLFetchError as exc:
                        failures.append(exc)
                if not last:
                    break  # hedge delay over or a mirror failed: start the next one
        raise failures[-1]

    async def fetch(
        self, cert: Any, *, use_deltas: Any = None
    ) -> Iterable[asn1_crl.CertificateList]:
        if not isinstance(cert, asn1_x509.Certificate) or not cert.ca:
            raise CRLFetchError("CRLs of end-entity certificates are never downloaded")
        key = issuer_serial(cert)
        if key in self._by_cert:
            return self._by_cert[key]
        urls = [
            point.url
            for point in get_relevant_crl_dps(cert, use_deltas=bool(use_deltas))
            if point.url.startswith("http")
        ]
        if not urls:
            raise CRLFetchError("the certificate has no HTTP CRL distribution point")
        try:
            found = await self._first(urls)
        except CRLFetchError:
            await asyncio.sleep(self._pause)
            found = await self._first(urls)
        self._by_cert[key] = [found]
        return self._by_cert[key]

    def fetched_crls(self) -> Iterable[asn1_crl.CertificateList]:
        return [crl for crls in self._by_cert.values() for crl in crls]

    def fetched_crls_for_cert(self, cert: Any) -> Iterable[asn1_crl.CertificateList]:
        return self._by_cert[issuer_serial(cert)]


def _caused_by_connect_timeout(error: BaseException) -> bool:
    """Whether a connection time-out is anywhere in the chain of causes of ``error``."""
    seen: set[int] = set()
    cause: BaseException | None = error.__cause__ or error.__context__
    while cause is not None and id(cause) not in seen:
        if isinstance(cause, requests.ConnectTimeout):
            return True
        seen.add(id(cause))
        cause = cause.__cause__ or cause.__context__
    return False


class RetryingOcspFetcher(OCSPFetcher):
    """Retries a failed OCSP request once, unless the connection itself timed out."""

    def __init__(self, inner: OCSPFetcher, pause: float = RETRY_PAUSE) -> None:
        self._inner = inner
        self._pause = pause

    async def fetch(self, cert: Any, authority: Any) -> asn1_ocsp.OCSPResponse:
        try:
            return await self._inner.fetch(cert, authority)
        except OCSPFetchError as exc:
            if _caused_by_connect_timeout(exc):
                raise
            await asyncio.sleep(self._pause)
            return await self._inner.fetch(cert, authority)

    def fetched_responses(self) -> Iterable[asn1_ocsp.OCSPResponse]:
        return self._inner.fetched_responses()

    def fetched_responses_for_cert(self, cert: Any) -> Iterable[asn1_ocsp.OCSPResponse]:
        return self._inner.fetched_responses_for_cert(cert)


class RevocationFetcherBackend(FetcherBackend):
    """HTTP fetchers (``requests``) with the two rules of this module."""

    def __init__(self, timeout: float) -> None:
        self._timeouts: Timeouts = (max(CONNECT_TIMEOUT, timeout), timeout)
        # pyHanko hands per_request_timeout to requests, which accepts (connect, read).
        self._inner = RequestsFetcherBackend(per_request_timeout=self._timeouts)  # type: ignore[no-untyped-call]

    def get_fetchers(self) -> Fetchers:
        fetchers = self._inner.get_fetchers()
        return Fetchers(
            ocsp_fetcher=RetryingOcspFetcher(fetchers.ocsp_fetcher),
            crl_fetcher=CaOnlyCrlFetcher(self._timeouts),
            cert_fetcher=fetchers.cert_fetcher,
        )


def revocation_fetchers(timeout: float) -> Fetchers:
    return RevocationFetcherBackend(timeout).get_fetchers()
