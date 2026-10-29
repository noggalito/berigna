# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Local history of operations (RF-082; configuracion-y-datos §4; AM-12, CS-11).

One row per signed or verified document: when, what, the file name (the full path only if
the user asks), the SHA-256 of the original and of the signed copy, the level, the signer and
the result. It is a record for the user's own control, not evidence: the signed PDF is. With
the SHA-256 a file can be matched to its row. It never holds the contents of documents nor
the full DNI (long numbers are masked), lives in a file only its owner can read, can be
switched off (``history-enabled``) and cleared.

Each call opens its own connection, so the worker threads of signing can record safely.
"""

import contextlib
import csv
import datetime as dt
import enum
import io
import os
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from berigna.core.i18n import Language, translations
from berigna.core.report import messages
from berigna.core.report.explanations import mask_numbers

_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation (
  id            INTEGER PRIMARY KEY,
  ts_utc        TEXT NOT NULL,
  kind          TEXT NOT NULL,
  file_name     TEXT NOT NULL,
  file_sha256   TEXT NOT NULL,
  signed_name   TEXT,
  signed_sha256 TEXT,
  format        TEXT,
  level         TEXT,
  signer_cn     TEXT,
  signer_serial TEXT,
  result        TEXT NOT NULL,
  detail        TEXT
)
"""


class Kind(enum.Enum):
    SIGN = "sign"
    BATCH = "batch"  # one row per document of a batch
    VERIFY = "verify"


@dataclass(frozen=True)
class Entry:
    moment: dt.datetime
    kind: Kind
    file_name: str  # name, or full path when the user chose so
    file_sha256: str
    result: str  # "ok", "error" or the ETSI indication of a verification
    signed_name: str | None = None
    signed_sha256: str | None = None
    level: str | None = None
    signer: str | None = None  # common name, long numbers masked
    signer_serial: str | None = None  # serial number of the certificate, hex
    detail: str | None = None  # ERR-xxx, or the counts of a verification
    format: str = "PAdES"


class History:
    def __init__(self, path: Path, *, full_path: bool = False) -> None:
        self.path = path
        self.full_path = full_path

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.path.exists():
            os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))  # CS-11
        connection = sqlite3.connect(self.path)
        connection.execute(_SCHEMA)
        return connection

    def name(self, path: Path) -> str:
        return str(path) if self.full_path else path.name

    def _session(self) -> contextlib.closing[sqlite3.Connection]:
        """A connection closed also when a statement fails (``with`` on a connection only
        commits or rolls back)."""
        return contextlib.closing(self._connect())

    def record(self, entry: Entry) -> None:
        with self._session() as connection, connection:
            connection.execute(
                "INSERT INTO operation (ts_utc, kind, file_name, file_sha256, signed_name, "
                "signed_sha256, format, level, signer_cn, signer_serial, result, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.moment.astimezone(dt.UTC).isoformat(),
                    entry.kind.value,
                    entry.file_name,
                    entry.file_sha256,
                    entry.signed_name,
                    entry.signed_sha256,
                    entry.format,
                    entry.level,
                    mask_numbers(entry.signer) if entry.signer else None,
                    entry.signer_serial,
                    entry.result,
                    entry.detail,
                ),
            )

    def entries(self, search: str = "") -> list[Entry]:
        """Newest first; ``search`` matches the file names, the signer and the SHA-256."""
        if not self.path.exists():
            return []
        pattern = f"%{search.strip()}%"
        with self._session() as connection:
            rows = connection.execute(
                "SELECT ts_utc, kind, file_name, file_sha256, result, signed_name, "
                "signed_sha256, level, signer_cn, signer_serial, detail, format "
                "FROM operation WHERE file_name LIKE ?1 OR signed_name LIKE ?1 "
                "OR signer_cn LIKE ?1 OR file_sha256 LIKE ?1 OR signed_sha256 LIKE ?1 "
                "ORDER BY id DESC",
                (pattern,),
            ).fetchall()
        return [
            Entry(
                moment=dt.datetime.fromisoformat(row[0]),
                kind=Kind(row[1]),
                file_name=row[2],
                file_sha256=row[3],
                result=row[4],
                signed_name=row[5],
                signed_sha256=row[6],
                level=row[7],
                signer=row[8],
                signer_serial=row[9],
                detail=row[10],
                format=row[11],
            )
            for row in rows
        ]

    def clear(self) -> None:
        if self.path.exists():
            with self._session() as connection:
                with connection:
                    connection.execute("DELETE FROM operation")
                connection.execute("VACUUM")  # leave no deleted rows in the file


def history_csv(entries: Sequence[Entry], language: Language = Language.ES_PE) -> str:
    """The history as CSV, for the user's own audit (RF-082)."""
    t = translations(language).gettext
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow([t(column) for column in messages.HISTORY_COLUMNS])
    for entry in entries:
        writer.writerow(
            [
                entry.moment.astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
                t(messages.HISTORY_KINDS[entry.kind.value]),
                entry.file_name,
                entry.file_sha256,
                entry.signed_name or "",
                entry.signed_sha256 or "",
                entry.level or "",
                entry.signer or "",
                entry.signer_serial or "",
                entry.result,
                entry.detail or "",
            ]
        )
    return out.getvalue()
