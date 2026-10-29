# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
import faulthandler
import logging
import sys
import threading
from collections.abc import Generator
from pathlib import Path

import pytest

from berigna.core import crashes


@pytest.fixture
def hooks() -> Generator[None, None, None]:
    """install() replaces process-wide hooks: always put the defaults back."""
    previous = sys.excepthook, threading.excepthook, faulthandler.is_enabled()
    yield
    crashes.uninstall()
    sys.excepthook, threading.excepthook = previous[0], previous[1]
    if previous[2]:
        faulthandler.enable()


def _raise(message: str) -> tuple[type[BaseException], BaseException, object]:
    try:
        raise RuntimeError(message)
    except RuntimeError:
        exc_type, value, tb = sys.exc_info()
        assert exc_type is not None
        assert value is not None
        return exc_type, value, tb


def test_recorded_failures_are_masked_logged_and_offered_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    exc_type, value, tb = _raise("certificado de PEREZ FIR 12345678 hard")
    with caplog.at_level(logging.CRITICAL, logger="berigna.crash"):
        crashes.record(exc_type, value, tb, directory=tmp_path)  # type: ignore[arg-type]
    assert "uncaught exception in the main thread" in caplog.text
    pending = tmp_path / crashes.PENDING_NAME
    assert pending.stat().st_mode & 0o777 == 0o600
    report = crashes.take_pending(tmp_path)
    assert report is not None
    assert report.startswith("[main thread]")
    assert "RuntimeError: certificado de PEREZ FIR ****5678 hard" in report
    assert "12345678" not in report
    assert not pending.exists()
    assert crashes.take_pending(tmp_path) is None


def test_the_pending_report_has_a_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(crashes, "MAX_PENDING", 10)
    for n in range(3):
        crashes.record(*_raise(f"fallo {n}"), directory=tmp_path)  # type: ignore[misc]
    report = crashes.take_pending(tmp_path)
    assert report is not None
    assert "fallo 0" in report
    assert "fallo 1" not in report


def test_recording_never_raises(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    blocker = tmp_path / "no-es-carpeta"
    blocker.write_text("")
    crashes.record(*_raise("sin carpeta"), directory=blocker)  # type: ignore[misc]
    assert "RuntimeError: sin carpeta" in capfd.readouterr().err


def test_install_keeps_a_native_crash_of_the_last_run(tmp_path: Path, hooks: None) -> None:
    (tmp_path / crashes.FAULTS_NAME).write_text(
        'Fatal Python error: Segmentation fault\n  File "preview.py", line 12\n'
    )
    crashes.install(tmp_path)
    assert sys.excepthook is crashes._excepthook
    assert threading.excepthook is crashes._threading_excepthook
    assert faulthandler.is_enabled()
    assert (tmp_path / crashes.FAULTS_NAME).read_text() == ""  # ready for this run
    report = crashes.take_pending(tmp_path)
    assert report is not None
    assert report.startswith("[fatal error in native code]")
    assert "Segmentation fault" in report
    crashes.install(tmp_path)  # a second install replaces the first cleanly
    assert crashes.take_pending(tmp_path) is None


def test_hooks_record_main_thread_and_worker_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hooks: None
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    crashes.install()
    sys.excepthook(*_raise("en el hilo principal"))  # type: ignore[arg-type]

    def work() -> None:
        raise ValueError("en el hilo de firma")

    worker = threading.Thread(target=work, name="berigna-sign")
    worker.start()
    worker.join()
    report = crashes.take_pending()
    assert report is not None
    assert "[main thread]" in report
    assert "RuntimeError: en el hilo principal" in report
    assert "[thread berigna-sign]" in report
    assert "ValueError: en el hilo de firma" in report


def test_interrupts_and_thread_exits_are_not_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hooks: None
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    seen: list[type[BaseException]] = []
    monkeypatch.setattr(sys, "__excepthook__", lambda exc_type, *_args: seen.append(exc_type))
    crashes.install()
    sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
    worker = threading.Thread(target=lambda: sys.exit(0))
    worker.start()
    worker.join()
    assert seen == [KeyboardInterrupt]
    assert crashes.take_pending() is None
