# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Technical log (RF-083).

A rotating log, five files of 1 MB, in ``$XDG_STATE_HOME/berigna/logs/`` (usually
``~/.local/state/berigna/logs/``), for support: levels ERROR, WARNING, INFO and, with
``BERIGNA_DEBUG=1``, DEBUG. It never holds the PIN (the code never logs it) nor the contents
of documents; every run of five or more digits, as the DNI in a certificate's name or a RUC,
is masked to its last four, also inside tracebacks.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from berigna.core.report.explanations import mask_numbers

MAX_BYTES = 1024 * 1024
BACKUPS = 4  # five files in all
LOG_NAME = "berigna.log"


def log_directory() -> Path:
    state = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(state) / "berigna" / "logs"


class MaskingFormatter(logging.Formatter):
    """Formats as usual, then masks long numbers in the whole text, traceback included."""

    def format(self, record: logging.LogRecord) -> str:
        return mask_numbers(super().format(record))


def setup_logging(directory: Path | None = None, *, debug: bool | None = None) -> Path:
    """Send the logs of berigna to the rotating file in ``directory``; return its path."""
    directory = directory or log_directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / LOG_NAME
    handler = RotatingFileHandler(path, maxBytes=MAX_BYTES, backupCount=BACKUPS, encoding="utf-8")
    handler.setFormatter(
        MaskingFormatter("%(asctime)s %(levelname)s %(name)s [%(threadName)s] %(message)s")
    )
    if debug is None:
        debug = os.environ.get("BERIGNA_DEBUG") == "1"
    logger = logging.getLogger("berigna")
    for old in [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]:
        logger.removeHandler(old)
        old.close()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    return path
