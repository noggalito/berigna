# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Cache and periodic refresh of the INDECOPI trusted list (ADR-0014 §5, RF-061)."""

import datetime as dt
from pathlib import Path

import pytest

from berigna.core.errors import TslError
from berigna.core.trust.cache import LIST_FILE, STATE_FILE, TslCache, refresh
from berigna.core.trust.tsl import TrustedList, load_tsl
from support.tsl import TslContent, TslPki, build_tsl, build_tsl_pki

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture(scope="module")
def tsl_pki() -> TslPki:
    return build_tsl_pki()


def _download(tsl_pki: TslPki, sequence: int, calls: list[int | None] | None = None):  # type: ignore[no-untyped-def]
    data = build_tsl(tsl_pki, TslContent(sequence=sequence))

    def download(minimum: int | None) -> tuple[TrustedList, bytes]:
        if calls is not None:
            calls.append(minimum)
        trusted = load_tsl(data, minimum_sequence=minimum, root=tsl_pki.root)
        return trusted, data

    return download


def test_first_run_downloads_and_keeps_the_list(tmp_path: Path, tsl_pki: TslPki) -> None:
    cache = TslCache(tmp_path, root=tsl_pki.root)
    calls: list[int | None] = []
    result = refresh(cache, download=_download(tsl_pki, 7, calls), now=NOW)
    assert result.downloaded
    assert result.trusted_list is not None
    assert result.trusted_list.sequence_number == 7
    assert calls == [None]
    state = cache.state()
    assert state is not None
    assert (state.sequence, state.fetched) == (7, NOW)
    loaded = cache.load()
    assert loaded is not None
    assert loaded.sequence_number == 7


def test_recent_cache_is_used_without_downloading(tmp_path: Path, tsl_pki: TslPki) -> None:
    cache = TslCache(tmp_path, root=tsl_pki.root)
    refresh(cache, download=_download(tsl_pki, 7), now=NOW)
    calls: list[int | None] = []
    later = NOW + dt.timedelta(hours=2)
    result = refresh(cache, download=_download(tsl_pki, 8, calls), now=later)
    assert (result.downloaded, calls) == (False, [])
    assert result.trusted_list is not None
    assert result.trusted_list.sequence_number == 7
    # "Update now" downloads anyway, and asks for nothing older than what was accepted.
    forced = refresh(cache, download=_download(tsl_pki, 8, calls), now=later, force=True)
    assert forced.downloaded
    assert calls == [7]


def test_old_cache_is_renewed(tmp_path: Path, tsl_pki: TslPki) -> None:
    cache = TslCache(tmp_path, root=tsl_pki.root)
    refresh(cache, download=_download(tsl_pki, 7), now=NOW)
    result = refresh(cache, download=_download(tsl_pki, 9), now=NOW + dt.timedelta(days=2))
    assert result.downloaded
    state = cache.state()
    assert state is not None
    assert state.sequence == 9


def test_offline_falls_back_to_the_cache_or_to_nothing(tmp_path: Path, tsl_pki: TslPki) -> None:
    def offline(_minimum: int | None) -> tuple[TrustedList, bytes]:
        raise TslError("cannot download")

    empty = TslCache(tmp_path / "vacia", root=tsl_pki.root)
    nothing = refresh(empty, download=offline, now=NOW)
    assert nothing.trusted_list is None
    assert isinstance(nothing.error, TslError)

    cache = TslCache(tmp_path, root=tsl_pki.root)
    refresh(cache, download=_download(tsl_pki, 7), now=NOW)
    stale = refresh(cache, download=offline, now=NOW + dt.timedelta(days=3))
    assert stale.trusted_list is not None
    assert stale.trusted_list.sequence_number == 7
    assert not stale.downloaded


def test_rollback_to_an_older_list_is_refused(tmp_path: Path, tsl_pki: TslPki) -> None:
    cache = TslCache(tmp_path, root=tsl_pki.root)
    refresh(cache, download=_download(tsl_pki, 9), now=NOW)
    older = refresh(cache, download=_download(tsl_pki, 8), now=NOW, force=True)
    assert isinstance(older.error, TslError)
    assert older.trusted_list is not None
    assert older.trusted_list.sequence_number == 9  # the accepted one stays
    # A cached file replaced by an older list is not trusted either.
    (tmp_path / LIST_FILE).write_bytes(build_tsl(tsl_pki, TslContent(sequence=8)))
    assert cache.load() is None


def test_damaged_cache_files(tmp_path: Path, tsl_pki: TslPki) -> None:
    cache = TslCache(tmp_path, root=tsl_pki.root)
    assert (cache.state(), cache.load()) == (None, None)
    refresh(cache, download=_download(tsl_pki, 7), now=NOW)
    (tmp_path / STATE_FILE).write_text("{roto")
    assert cache.state() is None
    (tmp_path / LIST_FILE).write_bytes(b"<no/>")
    assert cache.load() is None


def test_a_list_that_cannot_be_kept_is_still_used(tmp_path: Path, tsl_pki: TslPki) -> None:
    blocked = tmp_path / "archivo"
    blocked.write_text("")  # the cache directory cannot be created under a file
    cache = TslCache(blocked / "tsl", root=tsl_pki.root)
    result = refresh(cache, download=_download(tsl_pki, 7), now=NOW)
    assert result.trusted_list is not None
    assert result.downloaded


def test_default_download_fetches_from_indecopi(
    tmp_path: Path, tsl_pki: TslPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[int | None] = []

    def fake_fetch(*, minimum_sequence: int | None = None) -> tuple[TrustedList, bytes]:
        asked.append(minimum_sequence)
        return _download(tsl_pki, 7)(minimum_sequence)

    monkeypatch.setattr("berigna.core.trust.cache.fetch_tsl", fake_fetch)
    result = refresh(TslCache(tmp_path, root=tsl_pki.root), now=NOW)
    assert result.downloaded
    assert asked == [None]
