# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Fetchers of revocation data shared by the signer check, signing and verification.

Two rules apply everywhere berigna goes online for OCSP or CRLs:

- the CRL of an end-entity certificate is never downloaded: for the DNIe it weighs ~109 MB
  (RF-063). End-entity certificates are checked with OCSP; CRLs are fetched for CAs only.
- a failed request is retried once after a short pause. RENIEC's services have failed the
  first request after a while without use and answered the next one in ~1 s (R-17).
"""

import asyncio
from collections.abc import Iterable
from typing import Any

from asn1crypto import crl as asn1_crl
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from pyhanko_certvalidator.errors import CRLFetchError, OCSPFetchError
from pyhanko_certvalidator.fetchers.api import (
    CRLFetcher,
    FetcherBackend,
    Fetchers,
    OCSPFetcher,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend

RETRY_PAUSE = 0.5  # seconds


class CaOnlyCrlFetcher(CRLFetcher):
    """Fetches CRLs for CA certificates only, retrying a failed request once."""

    def __init__(self, inner: CRLFetcher, pause: float = RETRY_PAUSE) -> None:
        self._inner = inner
        self._pause = pause

    async def fetch(
        self, cert: Any, *, use_deltas: Any = None
    ) -> Iterable[asn1_crl.CertificateList]:
        if not isinstance(cert, asn1_x509.Certificate) or not cert.ca:
            raise CRLFetchError("CRLs of end-entity certificates are never downloaded")
        try:
            return await self._inner.fetch(cert, use_deltas=use_deltas)
        except CRLFetchError:
            await asyncio.sleep(self._pause)
            return await self._inner.fetch(cert, use_deltas=use_deltas)

    def fetched_crls(self) -> Iterable[asn1_crl.CertificateList]:
        return self._inner.fetched_crls()

    def fetched_crls_for_cert(self, cert: Any) -> Iterable[asn1_crl.CertificateList]:
        return self._inner.fetched_crls_for_cert(cert)


class RetryingOcspFetcher(OCSPFetcher):
    """Retries a failed OCSP request once."""

    def __init__(self, inner: OCSPFetcher, pause: float = RETRY_PAUSE) -> None:
        self._inner = inner
        self._pause = pause

    async def fetch(self, cert: Any, authority: Any) -> asn1_ocsp.OCSPResponse:
        try:
            return await self._inner.fetch(cert, authority)
        except OCSPFetchError:
            await asyncio.sleep(self._pause)
            return await self._inner.fetch(cert, authority)

    def fetched_responses(self) -> Iterable[asn1_ocsp.OCSPResponse]:
        return self._inner.fetched_responses()

    def fetched_responses_for_cert(self, cert: Any) -> Iterable[asn1_ocsp.OCSPResponse]:
        return self._inner.fetched_responses_for_cert(cert)


class RevocationFetcherBackend(FetcherBackend):
    """HTTP fetchers (``requests``) with the two rules of this module."""

    def __init__(self, timeout: float) -> None:
        self._inner = RequestsFetcherBackend(per_request_timeout=timeout)  # type: ignore[no-untyped-call]

    def get_fetchers(self) -> Fetchers:
        fetchers = self._inner.get_fetchers()
        return Fetchers(
            ocsp_fetcher=RetryingOcspFetcher(fetchers.ocsp_fetcher),
            crl_fetcher=CaOnlyCrlFetcher(fetchers.crl_fetcher),
            cert_fetcher=fetchers.cert_fetcher,
        )


def revocation_fetchers(timeout: float) -> Fetchers:
    return RevocationFetcherBackend(timeout).get_fetchers()
