# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Local history of operations (RF-082; AM-12, CS-11)."""

import csv
import datetime as dt
import io
import sqlite3
import stat
from pathlib import Path

import pytest

from berigna.core.history import Entry, History, Kind, history_csv

MOMENT = dt.datetime(2026, 10, 29, 5, 3, tzinfo=dt.UTC)


def _signed(history: History, name: str, result: str = "ok") -> Entry:
    entry = Entry(
        MOMENT,
        Kind.SIGN,
        history.name(Path("/home/rosa/Documentos") / name),
        "aa" * 32,
        result,
        signed_name=name.replace(".pdf", "-firmado.pdf"),
        signed_sha256="bb" * 32,
        level="B-B",
        signer="QUISPE MAMANI ROSA FIR 87654321 hard",
        signer_serial="29c6a33d",
    )
    history.record(entry)
    return entry


def test_records_newest_first_without_the_dni(tmp_path: Path) -> None:
    history = History(tmp_path / "berigna" / "history.sqlite3")
    assert history.entries() == []  # nothing yet, and no file created
    assert not history.path.exists()
    _signed(history, "contrato.pdf")
    _signed(history, "acta.pdf", "error")
    entries = history.entries()
    assert [e.file_name for e in entries] == ["acta.pdf", "contrato.pdf"]
    assert entries[1].signer == "QUISPE MAMANI ROSA FIR ****4321 hard"
    assert entries[1].moment == MOMENT
    assert b"87654321" not in history.path.read_bytes()
    # CS-11: only the owner can read it.
    assert stat.S_IMODE(history.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(history.path.parent.stat().st_mode) == 0o700


def test_full_path_only_when_asked(tmp_path: Path) -> None:
    assert History(tmp_path / "h").name(Path("/home/rosa/a.pdf")) == "a.pdf"
    assert History(tmp_path / "h", full_path=True).name(Path("/home/rosa/a.pdf")) == (
        "/home/rosa/a.pdf"
    )


def test_search_and_clear(tmp_path: Path) -> None:
    history = History(tmp_path / "history.sqlite3")
    _signed(history, "contrato.pdf")
    _signed(history, "acta.pdf")
    history.record(Entry(MOMENT, Kind.VERIFY, "otro.pdf", "cc" * 32, "TOTAL-PASSED", detail="1/1"))
    assert [e.file_name for e in history.entries("contr")] == ["contrato.pdf"]
    assert [e.file_name for e in history.entries("acta-firmado")] == ["acta.pdf"]
    assert [e.file_name for e in history.entries("cccc")] == ["otro.pdf"]  # by SHA-256
    assert len(history.entries("QUISPE")) == 2
    history.clear()
    assert history.entries() == []
    assert b"contrato" not in history.path.read_bytes()  # vacuumed
    History(tmp_path / "nunca.sqlite3").clear()  # nothing to clear


def test_csv(tmp_path: Path) -> None:
    history = History(tmp_path / "history.sqlite3")
    _signed(history, "contrato.pdf")
    history.record(Entry(MOMENT, Kind.VERIFY, "otro.pdf", "cc" * 32, "TOTAL-PASSED", detail="1/1"))
    rows = list(csv.reader(io.StringIO(history_csv(history.entries()))))
    assert rows[0][:3] == ["Fecha (UTC)", "Operación", "Archivo"]
    assert rows[1][:3] == ["2026-10-29T05:03:00Z", "Verificación", "otro.pdf"]
    assert rows[1][4:9] == ["", "", "", "", ""]
    assert rows[2][1] == "Firma"
    assert rows[2][7] == "QUISPE MAMANI ROSA FIR ****4321 hard"


def test_a_failing_statement_closes_its_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Signing threads and the interface share the file: no connection is left open."""
    closed: list[bool] = []

    class Tracked(sqlite3.Connection):
        def close(self) -> None:
            closed.append(True)
            super().close()

    real = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda path: real(path, factory=Tracked))
    history = History(tmp_path / "history.sqlite3")
    entry = Entry(MOMENT, Kind.SIGN, "contrato.pdf", "aa" * 32, "ok", level=object())  # type: ignore[arg-type]
    with pytest.raises(sqlite3.Error):
        history.record(entry)
    assert closed == [True]
    assert history.entries() == []
    assert len(closed) == 2
