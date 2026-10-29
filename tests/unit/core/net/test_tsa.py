# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""RFC 3161 client (RF-062): configuration and the probe run before the PIN."""

import asyncio
import socket
import threading
import time

import pytest

from berigna.core.errors import TsaError
from berigna.core.net.tsa import TsaSettings, http_timestamper, probe
from support.pki import Pki, build_pki
from support.tsa import local_tsa, make_timestamper


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The local TSA must be reached directly, whatever proxy the environment sets."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")


def test_probe_obtains_a_timestamp_over_http(pki: Pki) -> None:
    stamper, _ = make_timestamper(pki)
    with local_tsa(stamper) as url:
        client = http_timestamper(TsaSettings(url, timeout=5))
        probe(client)


def test_malformed_answer_is_a_tsa_error(pki: Pki) -> None:
    stamper, _ = make_timestamper(pki)
    with local_tsa(stamper, content_type="text/html") as url, pytest.raises(TsaError) as info:
        probe(http_timestamper(TsaSettings(url, timeout=5)))
    assert info.value.code == "ERR-305"


def test_unreachable_tsa_is_a_tsa_error() -> None:
    with socket.socket() as sock:  # a port nobody listens on
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with pytest.raises(TsaError):
        probe(http_timestamper(TsaSettings(f"http://127.0.0.1:{port}/tsr", timeout=2)))


def test_only_http_urls_are_accepted() -> None:
    with pytest.raises(TsaError):
        http_timestamper(TsaSettings("ftp://tsa.example/tsr"))


def test_credentials_are_sent_and_never_shown() -> None:
    settings = TsaSettings(
        "https://tsa.example/tsr",
        username="usuario",
        password="clave",  # noqa: S106 - test
    )
    client = http_timestamper(settings)
    assert client.auth == ("usuario", "clave")  # type: ignore[attr-defined]
    assert client.url.startswith("https://")  # type: ignore[attr-defined]
    assert "clave" not in repr(settings)
    assert http_timestamper(TsaSettings("http://tsa.example/tsr")).auth is None  # type: ignore[attr-defined]


class SilentTimeStamper:
    """A TSA that never answers (a hung connection)."""

    def __init__(self) -> None:
        self.release = threading.Event()

    async def async_dummy_response(self, md_algorithm: str) -> None:
        await asyncio.to_thread(self.release.wait, 5)


class BrokenTimeStamper:
    """A TSA client failing in a way pyHanko does not wrap."""

    async def async_dummy_response(self, md_algorithm: str) -> None:
        raise OSError("certificate verify failed")


def test_an_unusual_failure_is_reported_as_it_is() -> None:
    """Not as "did not answer within 30 s": the cause goes to the error and the log."""
    started = time.monotonic()
    with pytest.raises(TsaError, match="certificate verify failed"):
        probe(BrokenTimeStamper())  # type: ignore[arg-type]
    assert time.monotonic() - started < 2


def test_probe_gives_up_at_its_deadline() -> None:
    stamper = SilentTimeStamper()
    started = time.monotonic()
    with pytest.raises(TsaError, match="within"):
        probe(stamper, deadline=0.2)  # type: ignore[arg-type]
    assert time.monotonic() - started < 2
    stamper.release.set()
