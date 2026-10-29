# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Local record of unexpected failures (R-DES-11, BRG-DES-002 §5).

Nothing is ever sent (RNF-SEG-07). An exception nobody caught, in the main thread or in a
worker thread, goes to the technical log and to a pending report next to it, and is still
printed as before; a crash in C code (GTK, Poppler) is written by ``faulthandler`` to its
own file, and the next start moves it to the log and to the pending report. That start
offers the report once; it is removed when the user has answered.

Every entry says when it happened and with which version. Tracebacks carry no local
variables, so no PIN; every run of five or more digits is masked, and the home folder is
written as ``~``.
"""

import datetime as dt
import faulthandler
import logging
import sys
import threading
import traceback
from pathlib import Path
from types import TracebackType
from typing import TextIO

import berigna
from berigna.core.logs import log_directory
from berigna.core.report.explanations import mask_numbers

PENDING_NAME = "pending-failure.txt"
FAULTS_NAME = "faulthandler.txt"
MAX_PENDING = 64 * 1024  # a loop of failures must not fill the disk: the oldest text goes

log = logging.getLogger("berigna.crash")
_faults: TextIO | None = None
_directory: Path | None = None  # the one install() used, for the hooks
_default_thread_hook = threading.excepthook


def _redact(text: str) -> str:
    """Long numbers masked and the home folder, which names the user, written as ``~``."""
    return mask_numbers(text.replace(str(Path.home()), "~"))


def _append(path: Path, where: str, text: str) -> None:
    moment = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    entry = _redact(f"[{moment} · berigna {berigna.__version__} · {where}]\n{text.rstrip()}\n\n")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.touch(mode=0o600)
    try:
        previous = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        previous = ""
    path.write_text((previous + entry)[-MAX_PENDING:], encoding="utf-8")


def record(
    exc_type: type[BaseException],
    value: BaseException | None,
    tb: TracebackType | None,
    *,
    thread: str | None = None,
    directory: Path | None = None,
) -> None:
    """Log an uncaught exception and add it to the pending report; never raises."""
    where = f"thread {thread}" if thread else "main thread"
    text = "".join(traceback.format_exception(exc_type, value, tb))
    try:
        log.critical("uncaught exception in the %s\n%s", where, text.rstrip())
        _append((directory or _directory or log_directory()) / PENDING_NAME, where, text)
    except Exception:  # the hook must not fail in turn; stderr is the last resort
        if sys.__stderr__ is not None:
            sys.__stderr__.write(text)


def _excepthook(
    exc_type: type[BaseException], value: BaseException, tb: TracebackType | None
) -> None:
    if not issubclass(exc_type, KeyboardInterrupt):
        record(exc_type, value, tb)
    sys.__excepthook__(exc_type, value, tb)  # still printed, as without the hook


def _threading_excepthook(args: threading.ExceptHookArgs) -> None:
    if args.exc_type is not SystemExit:
        thread = args.thread.name if args.thread is not None else None
        record(args.exc_type, args.exc_value, args.exc_traceback, thread=thread)
    _default_thread_hook(args)


def install(directory: Path | None = None) -> None:
    """Install the hooks; first keep what ``faulthandler`` wrote if the last run crashed."""
    global _faults, _directory
    directory = directory or log_directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    faults = directory / FAULTS_NAME
    try:
        previous = faults.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        previous = ""
    if previous.strip():
        log.critical("fatal error in native code in the last run\n%s", previous.rstrip())
        _append(directory / PENDING_NAME, "fatal error in native code", previous)
    faults.touch(mode=0o600)
    if _faults is not None:
        faulthandler.disable()
        _faults.close()
    _faults = faults.open("w", encoding="utf-8")  # kept open: faulthandler writes to its fd
    faulthandler.enable(_faults)
    _directory = directory
    sys.excepthook = _excepthook
    threading.excepthook = _threading_excepthook


def uninstall() -> None:
    """Put back the default hooks and stop ``faulthandler`` (for the tests)."""
    global _faults, _directory
    sys.excepthook = sys.__excepthook__
    threading.excepthook = _default_thread_hook
    _directory = None
    if _faults is not None:
        faulthandler.disable()
        _faults.close()
        _faults = None


def pending(directory: Path | None = None) -> str | None:
    """The pending report, if any, already masked when it was written."""
    path = (directory or log_directory()) / PENDING_NAME
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except FileNotFoundError:
        return None
    return text or None


def clear_pending(directory: Path | None = None) -> None:
    """Remove the pending report once the user has seen it, so it is offered only once."""
    ((directory or log_directory()) / PENDING_NAME).unlink(missing_ok=True)
