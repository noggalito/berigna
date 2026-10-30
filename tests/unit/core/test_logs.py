# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Technical log (RF-083)."""

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from berigna.core.logs import (
    BACKUPS,
    LIBRARY_LOGGERS,
    MAX_BYTES,
    log_directory,
    setup_logging,
)


@pytest.fixture
def logger() -> Iterator[logging.Logger]:
    """setup_logging() changes process-wide loggers: put them back as they were."""
    loggers = [logging.getLogger(name) for name in ("berigna", *LIBRARY_LOGGERS)]
    saved = [(list(lg.handlers), lg.level, lg.propagate) for lg in loggers]
    yield loggers[0]
    for lg, (handlers, level, propagate) in zip(loggers, saved, strict=True):
        for handler in list(lg.handlers):
            if handler not in handlers:
                lg.removeHandler(handler)
                handler.close()
        lg.setLevel(level)
        lg.propagate = propagate


def test_log_directory_follows_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert log_directory() == tmp_path / "berigna" / "logs"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert log_directory() == Path.home() / ".local" / "state" / "berigna" / "logs"


def test_masks_long_numbers_also_in_tracebacks(logger: logging.Logger, tmp_path: Path) -> None:
    path = setup_logging(tmp_path / "logs", debug=False)
    log = logging.getLogger("berigna.core.prueba")
    log.debug("no se escribe en INFO")
    log.info("firmante %s", "QUISPE MAMANI ROSA FIR 87654321 hard")
    try:
        raise ValueError("RUC 20123456789")
    except ValueError:
        log.exception("fallo")
    text = path.read_text(encoding="utf-8")
    assert "FIR ****4321 hard" in text
    assert "RUC ****6789" in text
    assert "87654321" not in text
    assert "20123456789" not in text
    assert "no se escribe" not in text
    assert path.stat().st_mode & 0o777 != 0  # created
    assert (path.parent.stat().st_mode & 0o777) == 0o700


def test_rotation_and_debug(
    logger: logging.Logger, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BERIGNA_DEBUG", "1")
    path = setup_logging(tmp_path)
    path = setup_logging(tmp_path)  # set up twice: still one file handler
    handler = [h for h in logger.handlers if hasattr(h, "maxBytes")]
    assert len(handler) == 1
    assert (handler[0].maxBytes, handler[0].backupCount) == (MAX_BYTES, BACKUPS)  # type: ignore[attr-defined]
    logging.getLogger("berigna.x").debug("visible en DEBUG")
    assert "visible en DEBUG" in path.read_text(encoding="utf-8")


def test_library_tracebacks_go_to_the_log_not_the_terminal(
    logger: logging.Logger, tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    """issue of 2026-10-30: pyhanko_certvalidator printed "Failed to build path" and its
    traceback on the terminal, four times per verification."""
    path = setup_logging(tmp_path / "logs", debug=False)
    try:
        raise LookupError("no issuer for FIR 87654321 hard")
    except LookupError:
        logging.getLogger("pyhanko_certvalidator.context").warning(
            "Failed to build path", exc_info=True
        )
    logging.getLogger("pyhanko.sign.validation").info("No document timestamps after signature")
    assert capfd.readouterr().err == ""
    text = path.read_text(encoding="utf-8")
    assert "WARNING pyhanko_certvalidator.context" in text
    assert "LookupError: no issuer for FIR ****4321 hard" in text  # masked like the rest
    assert "No document timestamps" not in text  # below WARNING: not even in the log
