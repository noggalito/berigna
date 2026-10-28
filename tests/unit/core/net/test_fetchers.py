# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Revocation fetchers: never the CRL of an end-entity certificate (RF-063), hedged mirrors and
one retry (R-17), tolerant of RENIEC's slow connection set-up."""

import asyncio
import datetime as dt
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
import requests
from asn1crypto import crl as asn1_crl
from asn1crypto import pem
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko_certvalidator.errors import CRLFetchError, OCSPFetchError

from berigna.core.net import fetchers
from berigna.core.net.fetchers import (
    CONNECT_TIMEOUT,
    CaOnlyCrlFetcher,
    RetryingOcspFetcher,
    RevocationFetcherBackend,
    revocation_fetchers,
)
from support.pki import Pki, build_pki

TIMEOUTS = (1.0, 1.0)


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _ca(*urls: str) -> asn1_x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA CON ESPEJOS")])
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if urls:
        points = [
            x509.DistributionPoint([x509.UniformResourceIdentifier(u)], None, None, None)
            for u in urls
        ]
        builder = builder.add_extension(x509.CRLDistributionPoints(points), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def _leaf(pki: Pki) -> asn1_x509.Certificate:
    cert = pki.leaf("FIRMANTE")
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


class Mirrors:
    """Fake download: per-URL delay and outcome; records every request."""

    def __init__(self, behaviour: dict[str, tuple[float, bool]], crl: asn1_crl.CertificateList):
        self.behaviour = behaviour
        self.crl = crl
        self.calls: list[str] = []

    def __call__(self, url: str, timeouts: tuple[float, float]) -> asn1_crl.CertificateList:
        self.calls.append(url)
        delay, works = self.behaviour[url]
        time.sleep(delay)
        if not works:
            raise CRLFetchError(f"{url} timed out")
        return self.crl


@pytest.fixture(scope="module")
def crl(pki: Pki) -> asn1_crl.CertificateList:
    return asn1_crl.CertificateList.load(pki.arl())


def test_end_entity_crls_are_never_downloaded(pki: Pki, crl: asn1_crl.CertificateList) -> None:
    """RF-063: the CRL of the DNIe issuing CA weighs ~109 MB."""
    mirrors = Mirrors({}, crl)
    with pytest.raises(CRLFetchError, match="never downloaded"):
        asyncio.run(CaOnlyCrlFetcher(TIMEOUTS, download=mirrors).fetch(_leaf(pki)))
    assert mirrors.calls == []


def test_crl_is_fetched_once_and_cached(crl: asn1_crl.CertificateList) -> None:
    ca = _ca("http://crl.example/ca.crl")
    mirrors = Mirrors({"http://crl.example/ca.crl": (0, True)}, crl)
    fetcher = CaOnlyCrlFetcher(TIMEOUTS, download=mirrors)
    assert asyncio.run(fetcher.fetch(ca)) == [crl]
    assert asyncio.run(fetcher.fetch(ca)) == [crl]
    assert mirrors.calls == ["http://crl.example/ca.crl"]
    assert list(fetcher.fetched_crls()) == [crl]
    assert list(fetcher.fetched_crls_for_cert(ca)) == [crl]


def test_a_slow_mirror_is_hedged_with_the_next_one(crl: asn1_crl.CertificateList) -> None:
    """crl2.reniec.gob.pe takes ~15 s at times: the other mirror answers meanwhile."""
    slow, fast = "http://crl2.example/ca.crl", "http://crl.example/ca.crl"
    mirrors = Mirrors({slow: (0.5, True), fast: (0, True)}, crl)
    fetcher = CaOnlyCrlFetcher(TIMEOUTS, hedge=0.05, download=mirrors)
    started = time.monotonic()
    assert asyncio.run(fetcher.fetch(_ca(slow, fast))) == [crl]
    assert time.monotonic() - started < 0.4  # the slow mirror is not waited for
    assert mirrors.calls == [slow, fast]
    time.sleep(0.6)  # let the straggler finish after its event loop has closed


def test_a_fast_mirror_needs_no_second_connection(crl: asn1_crl.CertificateList) -> None:
    first, second = "http://crl.example/ca.crl", "http://crl2.example/ca.crl"
    mirrors = Mirrors({first: (0, True), second: (0, True)}, crl)
    asyncio.run(CaOnlyCrlFetcher(TIMEOUTS, hedge=1.0, download=mirrors).fetch(_ca(first, second)))
    assert mirrors.calls == [first]


def test_a_failed_mirror_starts_the_next_at_once(crl: asn1_crl.CertificateList) -> None:
    broken, good = "http://crl.example/ca.crl", "http://crl2.example/ca.crl"
    mirrors = Mirrors({broken: (0, False), good: (0, True)}, crl)
    fetcher = CaOnlyCrlFetcher(TIMEOUTS, hedge=10.0, download=mirrors)
    started = time.monotonic()
    assert asyncio.run(fetcher.fetch(_ca(broken, good))) == [crl]
    assert time.monotonic() - started < 2


@pytest.mark.parametrize("second_round_works", [True, False])
def test_all_mirrors_failing_is_retried_once(
    crl: asn1_crl.CertificateList, second_round_works: bool
) -> None:
    url = "http://crl.example/ca.crl"
    rounds = iter([False, second_round_works])

    def download(u: str, timeouts: tuple[float, float]) -> asn1_crl.CertificateList:
        if not next(rounds):
            raise CRLFetchError("timed out")
        return crl

    fetcher = CaOnlyCrlFetcher(TIMEOUTS, pause=0, download=download)
    if second_round_works:
        assert asyncio.run(fetcher.fetch(_ca(url))) == [crl]
    else:
        with pytest.raises(CRLFetchError):
            asyncio.run(fetcher.fetch(_ca(url)))


def test_ca_without_http_distribution_point(crl: asn1_crl.CertificateList) -> None:
    fetcher = CaOnlyCrlFetcher(TIMEOUTS, download=Mirrors({}, crl))
    with pytest.raises(CRLFetchError, match="no HTTP"):
        asyncio.run(fetcher.fetch(_ca("ldap://directorio.example/cn=ca")))


def test_late_answer_for_a_cancelled_request_is_dropped(crl: asn1_crl.CertificateList) -> None:
    release = threading.Event()

    async def scenario() -> None:
        future = fetchers._in_daemon_thread(lambda: release.wait(2) and crl)
        future.cancel()
        release.set()
        await asyncio.sleep(0.2)  # the thread delivers into an already finished future
        assert future.cancelled()

    asyncio.run(scenario())


# -- download over HTTP -------------------------------------------------------------------------


@contextmanager
def serving(status: int, body: bytes) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/ca.crl"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")


@pytest.mark.parametrize("armoured", [False, True], ids=["der", "pem"])
def test_download_der_and_pem(pki: Pki, armoured: bool) -> None:
    der = pki.arl()
    body = pem.armor("X509 CRL", der) if armoured else der
    with serving(200, body) as url:
        assert fetchers._download_crl(url, TIMEOUTS).dump() == der


def test_download_errors() -> None:
    with serving(404, b"no") as url, pytest.raises(CRLFetchError, match="HTTP 404"):
        fetchers._download_crl(url, TIMEOUTS)
    with serving(200, b"not a CRL") as url, pytest.raises(CRLFetchError):
        fetchers._download_crl(url, TIMEOUTS)
    with pytest.raises(CRLFetchError):
        fetchers._download_crl("http://127.0.0.1:9/ca.crl", TIMEOUTS)


# -- OCSP ---------------------------------------------------------------------------------------


class FlakyOcsp:
    def __init__(self, failures: int, cause: Exception | None = None) -> None:
        self.failures = failures
        self.cause = cause or requests.ReadTimeout("slow")
        self.calls = 0

    async def fetch(self, cert: Any, authority: Any) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise OCSPFetchError("failed") from self.cause
        return "answer"

    def fetched_responses(self) -> list[str]:
        return ["ocsp"]

    def fetched_responses_for_cert(self, cert: Any) -> list[str]:
        return ["ocsp-for-cert"]


@pytest.mark.parametrize(("failures", "succeeds"), [(0, True), (1, True), (2, False)])
def test_ocsp_is_retried_once(failures: int, succeeds: bool) -> None:
    inner = FlakyOcsp(failures)
    fetcher = RetryingOcspFetcher(inner, pause=0)  # type: ignore[arg-type]
    if succeeds:
        assert asyncio.run(fetcher.fetch("cert", "authority")) == "answer"
    else:
        with pytest.raises(OCSPFetchError):
            asyncio.run(fetcher.fetch("cert", "authority"))
    assert inner.calls == min(failures + 1, 2)
    assert list(fetcher.fetched_responses()) == ["ocsp"]
    assert list(fetcher.fetched_responses_for_cert("cert")) == ["ocsp-for-cert"]


def _wrapped(cause: BaseException) -> BaseException:
    outer = requests.ConnectionError("connection failed")
    outer.__cause__ = cause
    return outer


@pytest.mark.parametrize(
    "cause",
    [requests.ConnectTimeout("no SYN-ACK"), _wrapped(requests.ConnectTimeout("no SYN-ACK"))],
    ids=["directa", "envuelta"],
)
def test_ocsp_connection_timeout_is_not_retried(cause: BaseException) -> None:
    """After waiting CONNECT_TIMEOUT, a retry only doubled the wait (R-17)."""
    inner = FlakyOcsp(1, cause)  # type: ignore[arg-type]
    with pytest.raises(OCSPFetchError):
        asyncio.run(RetryingOcspFetcher(inner, pause=0).fetch("cert", "authority"))  # type: ignore[arg-type]
    assert inner.calls == 1


def test_cause_chain_with_a_cycle_ends() -> None:
    first, second = ValueError("a"), ValueError("b")
    first.__cause__, second.__cause__ = second, first
    assert not fetchers._caused_by_connect_timeout(first)


def test_http_fetchers_apply_the_rules() -> None:
    fetchers_ = revocation_fetchers(3.0)
    assert isinstance(fetchers_.crl_fetcher, CaOnlyCrlFetcher)
    assert isinstance(fetchers_.ocsp_fetcher, RetryingOcspFetcher)
    assert fetchers_.cert_fetcher is not None
    assert RevocationFetcherBackend(3.0)._timeouts == (CONNECT_TIMEOUT, 3.0)
    assert RevocationFetcherBackend(30.0)._timeouts == (30.0, 30.0)
