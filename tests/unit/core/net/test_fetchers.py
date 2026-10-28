# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Revocation fetchers: never the CRL of an end-entity certificate (RF-063), one retry (R-17)."""

import asyncio
from typing import Any

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives import serialization
from pyhanko_certvalidator.errors import CRLFetchError, OCSPFetchError

from berigna.core.net.fetchers import (
    CaOnlyCrlFetcher,
    RetryingOcspFetcher,
    revocation_fetchers,
)
from support.pki import Pki, build_pki


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _asn1(pki: Pki, which: str) -> asn1_x509.Certificate:
    cert = pki.ca if which == "ca" else pki.leaf("FIRMANTE")
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


class FlakyFetcher:
    """Fails the first ``failures`` calls, then answers; records every call."""

    def __init__(self, error: type[Exception], failures: int = 0) -> None:
        self.error = error
        self.failures = failures
        self.calls = 0

    async def _answer(self) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error("timed out")
        return "answer"

    async def fetch(self, *args: Any, **kwargs: Any) -> str:
        return await self._answer()

    def fetched_crls(self) -> list[str]:
        return ["crl"]

    def fetched_crls_for_cert(self, cert: Any) -> list[str]:
        return ["crl-for-cert"]

    def fetched_responses(self) -> list[str]:
        return ["ocsp"]

    def fetched_responses_for_cert(self, cert: Any) -> list[str]:
        return ["ocsp-for-cert"]


def test_end_entity_crls_are_never_downloaded(pki: Pki) -> None:
    """RF-063: the CRL of the DNIe issuing CA weighs ~109 MB."""
    inner = FlakyFetcher(CRLFetchError)
    fetcher = CaOnlyCrlFetcher(inner, pause=0)  # type: ignore[arg-type]
    with pytest.raises(CRLFetchError):
        asyncio.run(fetcher.fetch(_asn1(pki, "leaf")))
    assert inner.calls == 0
    assert asyncio.run(fetcher.fetch(_asn1(pki, "ca"))) == "answer"
    assert list(fetcher.fetched_crls()) == ["crl"]
    assert list(fetcher.fetched_crls_for_cert(_asn1(pki, "ca"))) == ["crl-for-cert"]


@pytest.mark.parametrize(("failures", "succeeds"), [(1, True), (2, False)])
def test_ca_crl_is_retried_once(pki: Pki, failures: int, succeeds: bool) -> None:
    inner = FlakyFetcher(CRLFetchError, failures=failures)
    fetcher = CaOnlyCrlFetcher(inner, pause=0)  # type: ignore[arg-type]
    if succeeds:
        assert asyncio.run(fetcher.fetch(_asn1(pki, "ca"))) == "answer"
    else:
        with pytest.raises(CRLFetchError):
            asyncio.run(fetcher.fetch(_asn1(pki, "ca")))
    assert inner.calls == 2


@pytest.mark.parametrize(("failures", "succeeds"), [(0, True), (1, True), (2, False)])
def test_ocsp_is_retried_once(failures: int, succeeds: bool) -> None:
    inner = FlakyFetcher(OCSPFetchError, failures=failures)
    fetcher = RetryingOcspFetcher(inner, pause=0)  # type: ignore[arg-type]
    if succeeds:
        assert asyncio.run(fetcher.fetch("cert", "authority")) == "answer"
    else:
        with pytest.raises(OCSPFetchError):
            asyncio.run(fetcher.fetch("cert", "authority"))
    assert inner.calls == min(failures + 1, 2)
    assert list(fetcher.fetched_responses()) == ["ocsp"]
    assert list(fetcher.fetched_responses_for_cert("cert")) == ["ocsp-for-cert"]


def test_http_fetchers_apply_both_rules() -> None:
    fetchers = revocation_fetchers(3.0)
    assert isinstance(fetchers.crl_fetcher, CaOnlyCrlFetcher)
    assert isinstance(fetchers.ocsp_fetcher, RetryingOcspFetcher)
    assert fetchers.cert_fetcher is not None
