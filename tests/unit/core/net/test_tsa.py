# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""RFC 3161 client (RF-062): configuration and the probe run before the PIN."""

import asyncio
import hashlib
import socket
import threading
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pyhanko.sign.timestamps.common_utils import TimestampRequestError

from berigna.core.errors import TsaError
from berigna.core.net.tsa import TsaSettings, check_token, http_timestamper, probe
from support.net import damaged
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


_DIGEST = hashlib.sha256(b"documento").digest()


def test_a_token_is_checked_before_it_is_embedded(pki: Pki) -> None:
    """R-DES-07: pyHanko checks the status and the nonce of the answer, not the token's
    signature; berigna does, before writing it into a signature."""
    stamper, _ = make_timestamper(pki)
    token = asyncio.run(stamper.async_timestamp(_DIGEST, "sha256"))
    check_token(token, _DIGEST, "sha256")
    with pytest.raises(TimestampRequestError, match="requested digest"):
        check_token(token, hashlib.sha256(b"otro").digest(), "sha256")
    with pytest.raises(TimestampRequestError, match="requested digest"):
        check_token(token, _DIGEST, "sha512")  # the same bytes, said to be another hash
    der = token.dump()
    signature = token["content"]["signer_infos"][0]["signature"].native
    broken = der.replace(signature, bytes([signature[0] ^ 1]) + signature[1:])
    assert broken != der
    with pytest.raises(TimestampRequestError, match="does not verify"):
        check_token(type(token).load(broken), _DIGEST, "sha256")


def test_a_damaged_answer_of_the_tsa_is_a_tsa_error(pki: Pki) -> None:
    """R-DES-07: the TSA answers over plain HTTP. A damaged answer gives a token that
    checks, or TimestampRequestError (TsaError, ERR-305, in signing): it reached the user as
    ERR-000, or as a signature written with a broken token and reported as done. One
    server for every example: stopping it costs half a second."""
    stamper, _ = make_timestamper(pki)
    damage: dict[str, int | bool] = {}

    def answer(_number: int, sent: bytes) -> bytes:
        return damaged(sent, int(damage["position"]), int(damage["byte"]), bool(damage["cut"]))

    with local_tsa(stamper, answer=answer) as url:
        client = http_timestamper(TsaSettings(url, timeout=5))

        @settings(max_examples=60, deadline=None)
        @given(position=st.integers(min_value=0), byte=st.integers(0, 255), cut=st.booleans())
        def check(position: int, byte: int, cut: bool) -> None:
            damage.update(position=position, byte=byte, cut=cut)
            try:
                token = asyncio.run(client.async_timestamp(_DIGEST, "sha256"))
            except TimestampRequestError:
                return
            check_token(token, _DIGEST, "sha256")

        check()
