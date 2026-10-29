# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
import faulthandler
import logging
import re
import sys
import threading
from collections.abc import Generator
from pathlib import Path
from types import TracebackType

import pytest

import berigna
from berigna.core import crashes

HEADER = re.compile(r"^\[\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00 · berigna (\S+) · (.+)\]$")


@pytest.fixture
def hooks() -> Generator[None, None, None]:
    """install() replaces process-wide hooks: always put the defaults back."""
    previous = sys.excepthook, threading.excepthook, faulthandler.is_enabled()
    yield
    crashes.uninstall()
    sys.excepthook, threading.excepthook = previous[0], previous[1]
    if previous[2]:
        faulthandler.enable()


def _raise(message: str) -> tuple[type[BaseException], BaseException, TracebackType | None]:
    try:
        raise RuntimeError(message)
    except RuntimeError:
        exc_type, value, tb = sys.exc_info()
        assert exc_type is not None
        assert value is not None
        return exc_type, value, tb


def _headers(report: str) -> list[tuple[str, str]]:
    return [m.groups() for line in report.splitlines() if (m := HEADER.match(line))]


def test_recorded_failures_are_dated_masked_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.CRITICAL, logger="berigna.crash"):
        crashes.record(*_raise("certificado de PEREZ FIR 12345678 hard"), directory=tmp_path)
    assert "uncaught exception in the main thread" in caplog.text
    pending = tmp_path / crashes.PENDING_NAME
    assert pending.stat().st_mode & 0o777 == 0o600
    report = crashes.pending(tmp_path)
    assert report is not None
    assert _headers(report) == [(berigna.__version__, "main thread")]
    assert "RuntimeError: certificado de PEREZ FIR ****5678 hard" in report
    assert "12345678" not in report


def test_the_report_stays_until_cleared(tmp_path: Path) -> None:
    crashes.record(*_raise("fallo"), directory=tmp_path)
    assert crashes.pending(tmp_path) == crashes.pending(tmp_path)  # reading does not remove
    crashes.clear_pending(tmp_path)
    assert crashes.pending(tmp_path) is None
    crashes.clear_pending(tmp_path)  # nothing to remove: no error


def test_the_home_folder_is_not_in_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", "/home/juan.perez")
    crashes.record(*_raise("No existe /home/juan.perez/Contrato.pdf"), directory=tmp_path)
    report = crashes.pending(tmp_path)
    assert report is not None
    assert "juan.perez" not in report
    assert "No existe ~/Contrato.pdf" in report


def test_the_report_keeps_the_newest_text_within_its_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(crashes, "MAX_PENDING", 400)
    for n in range(5):
        crashes.record(*_raise(f"fallo {n}"), directory=tmp_path)
    report = crashes.pending(tmp_path)
    assert report is not None
    assert len(report) <= 400
    assert "fallo 4" in report
    assert "fallo 0" not in report


def test_recording_never_raises(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    blocker = tmp_path / "no-es-carpeta"
    blocker.write_text("")
    crashes.record(*_raise("sin carpeta"), directory=blocker)
    assert "RuntimeError: sin carpeta" in capfd.readouterr().err


def test_install_logs_and_keeps_a_native_crash_of_the_last_run(
    tmp_path: Path, hooks: None, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / crashes.FAULTS_NAME).write_text(
        'Fatal Python error: Segmentation fault\n  File "preview.py", line 12\n'
    )
    with caplog.at_level(logging.CRITICAL, logger="berigna.crash"):
        crashes.install(tmp_path)
    assert "Segmentation fault" in caplog.text  # in the technical log too
    assert sys.excepthook is crashes._excepthook
    assert threading.excepthook is crashes._threading_excepthook
    assert faulthandler.is_enabled()
    assert (tmp_path / crashes.FAULTS_NAME).read_text() == ""  # ready for this run
    report = crashes.pending(tmp_path)
    assert report is not None
    assert _headers(report) == [(berigna.__version__, "fatal error in native code")]
    assert "Segmentation fault" in report
    crashes.clear_pending(tmp_path)
    crashes.install(tmp_path)  # a second install replaces the first cleanly
    assert crashes.pending(tmp_path) is None


def test_hooks_record_in_the_installed_folder_and_still_print(
    tmp_path: Path, hooks: None, capfd: pytest.CaptureFixture[str]
) -> None:
    crashes.install(tmp_path)
    sys.excepthook(*_raise("en el hilo principal"))

    def work() -> None:
        raise ValueError("en el hilo de firma")

    worker = threading.Thread(target=work, name="berigna-sign")
    worker.start()
    worker.join()
    report = crashes.pending(tmp_path)
    assert report is not None
    assert [where for _version, where in _headers(report)] == [
        "main thread",
        "thread berigna-sign",
    ]
    assert "RuntimeError: en el hilo principal" in report
    assert "ValueError: en el hilo de firma" in report
    printed = capfd.readouterr().err  # the default hooks still print to the terminal
    assert "RuntimeError: en el hilo principal" in printed
    assert "ValueError: en el hilo de firma" in printed


def test_interrupts_and_thread_exits_are_not_failures(tmp_path: Path, hooks: None) -> None:
    crashes.install(tmp_path)
    sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
    worker = threading.Thread(target=lambda: sys.exit(0))
    worker.start()
    worker.join()
    assert crashes.pending(tmp_path) is None
