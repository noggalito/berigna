# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""RFC 3161 time-stamping client (RF-062).

The protocol work (request with nonce, check of status, nonce and message imprint) is pyHanko's
``HTTPTimeStamper``; this module adds the configuration berigna exposes and a probe that is run
before the PIN is requested, so an unreachable TSA does not cost the user a PIN entry.
"""

import asyncio
import threading
from dataclasses import dataclass, field

import requests
from asn1crypto import tsp
from pyhanko.sign.timestamps import HTTPTimeStamper, TimeStamper
from pyhanko.sign.timestamps.common_utils import TimestampRequestError

from berigna.core.errors import TsaError


@dataclass(frozen=True)
class TsaSettings:
    """Where and how to reach a TSA (preferences, RF-062)."""

    url: str
    timeout: float = 10.0
    username: str | None = None
    password: str | None = field(default=None, repr=False)


class _HttpTimeStamper(HTTPTimeStamper):
    """pyHanko's client with the request made in the calling thread.

    pyHanko sends it through ``asyncio.to_thread``, whose worker threads are not daemons: a
    hung TSA would keep the whole application from exiting. Same checks as pyHanko's.
    """

    async def async_request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        try:
            response = requests.post(
                self.url,
                req.dump(),
                headers=self.request_headers(),
                auth=self.auth,
                timeout=self.timeout,
            )
        except OSError as exc:
            raise TimestampRequestError("Error in communication with timestamp server") from exc
        if response.headers.get("Content-Type") != "application/timestamp-reply":
            raise TimestampRequestError("Timestamp server response is malformed.", response)
        return tsp.TimeStampResp.load(response.content)


def http_timestamper(settings: TsaSettings) -> TimeStamper:
    if not settings.url.startswith(("http://", "https://")):
        raise TsaError(f"not an HTTP(S) URL: {settings.url!r}")
    auth = (settings.username, settings.password or "") if settings.username else None
    return _HttpTimeStamper(  # type: ignore[no-untyped-call]
        settings.url,
        https=settings.url.startswith("https://"),
        timeout=settings.timeout,
        auth=auth,
    )


def probe(timestamper: TimeStamper, md_algorithm: str = "sha256", deadline: float = 30.0) -> None:
    """Obtain one time-stamp over a dummy digest; raise :class:`TsaError` if that fails.

    pyHanko caches the answer and reuses it to reserve space in the signature.

    ``deadline`` bounds the whole exchange. The ``requests`` timeout applies to each network
    operation, not to the request: with a broken IPv6 route, urllib3 waits that long for every
    IPv6 address of the TSA before trying IPv4 (seen with freetsa.org, 2026-10-27). The request
    runs in a daemon thread that is left behind if it does not finish in time.
    """
    outcome: list[BaseException | None] = []

    def request() -> None:
        try:
            asyncio.run(timestamper.async_dummy_response(md_algorithm))
            outcome.append(None)
        except (TimestampRequestError, ValueError) as exc:
            outcome.append(exc)

    worker = threading.Thread(target=request, name="berigna-tsa-probe", daemon=True)
    worker.start()
    worker.join(deadline)
    if not outcome:
        raise TsaError(f"the TSA did not answer within {deadline:g} s")
    if outcome[0] is not None:
        raise TsaError(f"the TSA did not issue a time-stamp: {outcome[0]}") from outcome[0]
