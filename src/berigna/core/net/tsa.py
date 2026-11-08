# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""RFC 3161 time-stamping client (RF-062).

The protocol work (request with nonce, check of status, nonce and message imprint) is pyHanko's
``HTTPTimeStamper``; this module adds the configuration berigna exposes and a probe that is run
before the PIN is requested, so an unreachable TSA does not cost the user a PIN entry.
"""

import asyncio
import hashlib
import threading
from dataclasses import dataclass, field

import requests
from asn1crypto import cms, tsp
from pyhanko.sign.general import extract_signer_info
from pyhanko.sign.timestamps import HTTPTimeStamper, TimeStamper
from pyhanko.sign.timestamps.common_utils import TimestampRequestError
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.generic_cms import extract_certs_for_validation, validate_sig_integrity

from berigna.core.errors import TsaError


@dataclass(frozen=True)
class TsaSettings:
    """Where and how to reach a TSA (preferences, RF-062)."""

    url: str
    timeout: float = 10.0
    username: str | None = None
    password: str | None = field(default=None, repr=False)


# What a damaged answer raises in asn1crypto and pyHanko (R-DES-07: the mutations of the
# answer reached the user as ERR-000 or, worse, as a signature written with a broken token).
_UNREADABLE = (
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    IndexError,
    SignatureValidationError,
)


def check_token(token: cms.ContentInfo, message_digest: bytes) -> None:
    """Raise :class:`TimestampRequestError` unless ``token`` can be read in full and is
    signed, by the certificate it carries, over a ``TSTInfo`` with ``message_digest``.

    pyHanko checks the status and the nonce of the answer, not the token's own signature: an
    answer damaged on the way (the TSA answers over plain HTTP) would be written into the
    signature, which would then be TOTAL-FAILED. Whether the TSA is trusted is checked
    apart, by the validation of the signature."""
    try:
        token.native  # noqa: B018 - asn1crypto parses lazily: every field, now
        signed_data = token["content"]
        signer = extract_certs_for_validation(signed_data).signer_cert
        signer_info = extract_signer_info(signed_data)
        content = signed_data["encap_content_info"]
        raw = bytes(content["content"])
        digest = hashlib.new(signer_info["digest_algorithm"]["algorithm"].native, raw).digest()
        intact, valid = validate_sig_integrity(
            signer_info,
            signer,
            expected_content_type=content["content_type"].native,
            actual_digest=digest,
        )
        imprint = content["content"].parsed["message_imprint"]["hashed_message"].native
    except _UNREADABLE as exc:
        raise TimestampRequestError(f"the time-stamp token cannot be read: {exc}") from exc
    if not (intact and valid):
        raise TimestampRequestError("the signature of the time-stamp token does not verify")
    if imprint != message_digest:
        raise TimestampRequestError("the time-stamp token is not over the requested digest")


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
        try:
            return tsp.TimeStampResp.load(response.content)
        except ValueError as exc:
            raise TimestampRequestError(f"the answer of the TSA cannot be read: {exc}") from exc

    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> cms.ContentInfo:
        """pyHanko's, and then the token itself is checked (:func:`check_token`)."""
        try:
            token: cms.ContentInfo = await super().async_timestamp(message_digest, md_algorithm)
        except _UNREADABLE as exc:  # in pyHanko's reading of the answer
            raise TimestampRequestError(f"the answer of the TSA cannot be read: {exc}") from exc
        check_token(token, message_digest)
        return token


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
        except Exception as exc:  # reported below as what it is, not as a timeout
            outcome.append(exc)

    worker = threading.Thread(target=request, name="berigna-tsa-probe", daemon=True)
    worker.start()
    worker.join(deadline)
    if not outcome:
        raise TsaError(f"the TSA did not answer within {deadline:g} s")
    if outcome[0] is not None:
        raise TsaError(f"the TSA did not issue a time-stamp: {outcome[0]}") from outcome[0]
