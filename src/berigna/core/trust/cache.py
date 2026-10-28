# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""The last accepted INDECOPI trusted list, kept between runs (ADR-0014 §5, RF-061).

The cache holds the list as downloaded and the state of the last download: its sequence number,
which later lists may not go below (rollback), and when it was fetched. A cached list is
verified again every time it is read (signature under the pinned root, validity, NextUpdate,
sequence). The signer's CRL is not kept: revocation was checked, with a current CRL, when the
list was accepted, and an out-of-date copy would only make a valid list unusable offline.

:func:`refresh` downloads a new list when the cached one is older than ``max_age`` and falls
back to the cached one, or to nothing (the bundled store), when the download fails.
"""

import contextlib
import datetime as dt
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from berigna.core.errors import TslError
from berigna.core.files import write_atomically
from berigna.core.trust.tsl import TrustedList, fetch_tsl, load_tsl

LIST_FILE = "tsl-pe.xml"
STATE_FILE = "estado.json"
MAX_AGE = dt.timedelta(days=1)

Download = Callable[[int | None], tuple[TrustedList, bytes]]  # minimum sequence -> list, bytes


@dataclass(frozen=True)
class TslState:
    sequence: int
    fetched: dt.datetime


@dataclass(frozen=True)
class TslRefresh:
    """Outcome of :func:`refresh`: the list to use (None: bundled store only) and why."""

    trusted_list: TrustedList | None
    downloaded: bool
    error: TslError | None = None


class TslCache:
    def __init__(self, directory: Path, *, root: x509.Certificate | None = None) -> None:
        self.directory = directory
        self._root = root  # tests use their own INDECOPI-like root

    def state(self) -> TslState | None:
        try:
            raw = json.loads((self.directory / STATE_FILE).read_text(encoding="utf-8"))
            return TslState(int(raw["sequence"]), dt.datetime.fromisoformat(raw["fetched"]))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def load(self, moment: dt.datetime | None = None) -> TrustedList | None:
        """The cached list if it still verifies; None if there is none or it does not."""
        state = self.state()
        try:
            data = (self.directory / LIST_FILE).read_bytes()
            return load_tsl(
                data,
                moment=moment,
                minimum_sequence=state.sequence if state else None,
                root=self._root,
            )
        except (OSError, TslError):
            return None

    def save(self, data: bytes, trusted_list: TrustedList, fetched: dt.datetime) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        write_atomically(self.directory / LIST_FILE, data, replace=True)
        state = {"sequence": trusted_list.sequence_number, "fetched": fetched.isoformat()}
        write_atomically(self.directory / STATE_FILE, json.dumps(state).encode(), replace=True)


def refresh(
    cache: TslCache,
    *,
    download: Download | None = None,
    max_age: dt.timedelta = MAX_AGE,
    now: dt.datetime | None = None,
    force: bool = False,
) -> TslRefresh:
    """The trusted list to use now, downloading a new one when the cached one is too old."""
    when = now or dt.datetime.now(dt.UTC)
    state = cache.state()
    cached = cache.load(when)
    if cached is not None and state is not None and not force and when - state.fetched < max_age:
        return TslRefresh(cached, downloaded=False)
    fetch = download or (lambda minimum: fetch_tsl(minimum_sequence=minimum))
    try:
        trusted_list, data = fetch(state.sequence if state else None)
    except TslError as exc:
        return TslRefresh(cached, downloaded=False, error=exc)
    with contextlib.suppress(OSError):  # a list that cannot be kept is still good for this run
        cache.save(data, trusted_list, when)
    return TslRefresh(trusted_list, downloaded=True)
