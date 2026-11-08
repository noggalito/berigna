# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""A network that answers every OCSP request and every CRL download with the given bytes:
for the damaged answers of R-DES-07, without opening a socket."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
import requests

from berigna.core.net import fetchers


class _Answer:
    status_code = 200

    def __init__(self, content: bytes, content_type: str) -> None:
        self.content = content
        self.headers = {"Content-Type": content_type}


@contextmanager
def answering(*, ocsp: bytes, crl: bytes) -> Iterator[None]:
    """OCSP is POSTed (pyhanko-certvalidator), the CRLs of the CAs are fetched with GET
    (berigna's own client, ``core.net.fetchers``)."""

    def post(*_args: Any, **_kwargs: Any) -> _Answer:
        return _Answer(ocsp, "application/ocsp-response")

    def get(*_args: Any, **_kwargs: Any) -> _Answer:
        return _Answer(crl, "application/pkix-crl")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(fetchers, "RETRY_PAUSE", 0.0)  # every damaged answer is retried once
        patch.setattr(requests, "post", post)
        patch.setattr(requests, "get", get)
        yield


def damaged(data: bytes, position: int, byte: int, truncate: bool) -> bytes:
    """``data`` cut at ``position`` or with the byte there replaced by ``byte``: what a
    broken connection or someone on the plain HTTP of OCSP, CRL and TSA can deliver."""
    index = position % len(data)
    return data[:index] if truncate else data[:index] + bytes([byte]) + data[index + 1 :]
