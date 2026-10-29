# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Test time-stamping units: in memory, failing on demand, and over HTTP on localhost."""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from asn1crypto import keys as asn1_keys
from asn1crypto import tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.sign.timestamps.common_utils import TimestampRequestError
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from support.pki import Pki


class FlakyTimeStamper(DummyTimeStamper):
    """Answers like a TSA, but fails the calls whose numbers are in ``fail_on`` (1-based).

    pyHanko asks once for a dummy token (size estimation), then for each real time-stamp:
    call 1 is the dummy, 2 the signature time-stamp, 3 the document time-stamp of B-LTA.
    """

    def __init__(self, *args: Any, fail_on: frozenset[int] = frozenset(), **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fail_on = fail_on
        self.calls = 0

    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> Any:
        self.calls += 1
        if self.calls in self.fail_on:
            raise TimestampRequestError("TSA unavailable")
        return await super().async_timestamp(message_digest, md_algorithm)


def _asn1(cert: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def make_timestamper(
    pki: Pki, fail_on: frozenset[int] = frozenset()
) -> tuple[FlakyTimeStamper, x509.Certificate]:
    cert, key = pki.tsa()
    der_key = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    embedded = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    embedded.register(_asn1(pki.ca))
    stamper = FlakyTimeStamper(
        tsa_cert=_asn1(cert),
        tsa_key=asn1_keys.PrivateKeyInfo.load(der_key),
        certs_to_embed=embedded,
        fail_on=fail_on,
    )
    return stamper, cert


@contextmanager
def local_tsa(
    stamper: DummyTimeStamper, *, content_type: str = "application/timestamp-reply"
) -> Iterator[str]:
    """Serve ``stamper`` over HTTP on 127.0.0.1 (RFC 3161 §3.4); yields the URL."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            answer = stamper.request_tsa_response(tsp.TimeStampReq.load(body)).dump()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/tsr"
    finally:
        server.shutdown()
        server.server_close()
