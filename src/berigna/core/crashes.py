# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Local record of unexpected failures (R-DES-11, BRG-DES-002 §5).

Nothing is ever sent (RNF-SEG-07). An exception nobody caught, in the main thread or in a
worker thread, goes to the technical log and to a pending report next to it; a crash in C
code (GTK, Poppler) is written by ``faulthandler`` to its own file, read at the next start.
On that next start the interface tells the user once and offers to copy the report.

Tracebacks carry no local variables, so no PIN; every run of five or more digits is masked.
"""

import faulthandler
import logging
import sys
import threading
import traceback
from pathlib import Path
from types import TracebackType
from typing import TextIO

from berigna.core.logs import log_directory
from berigna.core.report.explanations import mask_numbers

PENDING_NAME = "pending-failure.txt"
FAULTS_NAME = "faulthandler.txt"
MAX_PENDING = 64 * 1024  # a loop of failures must not fill the disk

log = logging.getLogger("berigna.crash")
_faults: TextIO | None = None
_default_thread_hook = threading.excepthook


def _append(path: Path, text: str) -> None:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        size = 0
    if size >= MAX_PENDING:
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.touch(mode=0o600)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(mask_numbers(text).rstrip("\n") + "\n\n")


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
        _append((directory or log_directory()) / PENDING_NAME, f"[{where}]\n{text}")
    except Exception:  # the hook must not fail in turn; stderr is the last resort
        if sys.__stderr__ is not None:
            sys.__stderr__.write(text)


def _excepthook(
    exc_type: type[BaseException], value: BaseException, tb: TracebackType | None
) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, value, tb)
        return
    record(exc_type, value, tb)


def _threading_excepthook(args: threading.ExceptHookArgs) -> None:
    if args.exc_type is SystemExit:
        return
    thread = args.thread.name if args.thread is not None else None
    record(args.exc_type, args.exc_value, args.exc_traceback, thread=thread)


def install(directory: Path | None = None) -> None:
    """Install the hooks; first keep what ``faulthandler`` wrote if the last run crashed."""
    global _faults
    directory = directory or log_directory()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    faults = directory / FAULTS_NAME
    try:
        previous = faults.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        previous = ""
    if previous.strip():
        _append(directory / PENDING_NAME, f"[fatal error in native code]\n{previous}")
    faults.touch(mode=0o600)
    if _faults is not None:
        faulthandler.disable()
        _faults.close()
    _faults = faults.open("w", encoding="utf-8")  # kept open: faulthandler writes to its fd
    faulthandler.enable(_faults)
    sys.excepthook = _excepthook
    threading.excepthook = _threading_excepthook


def uninstall() -> None:
    """Put back the default hooks and stop ``faulthandler`` (for the tests)."""
    global _faults
    sys.excepthook = sys.__excepthook__
    threading.excepthook = _default_thread_hook
    if _faults is not None:
        faulthandler.disable()
        _faults.close()
        _faults = None


def take_pending(directory: Path | None = None) -> str | None:
    """The pending report, if any, removed so that it is offered only once."""
    path = (directory or log_directory()) / PENDING_NAME
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        path.unlink()
    except FileNotFoundError:
        return None
    return mask_numbers(text).strip() or None
