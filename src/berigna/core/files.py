# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Writing files safely: atomically, with fsync, and never over a file unless asked."""

import os
import tempfile
from pathlib import Path

from berigna.core.errors import OutputExistsError


def _umask(status: Path = Path("/proc/self/status")) -> int:
    """The process umask, read without changing it (os.umask would, for every thread);
    the usual 022 if it cannot be read."""
    try:
        for line in status.read_text().splitlines():
            if line.startswith("Umask:"):
                return int(line.split()[1], 8)
    except OSError:
        pass
    return 0o022


def write_atomically(path: Path, data: bytes, *, replace: bool = False) -> None:
    """Write ``data`` to ``path`` with fsync, all or nothing (RNF-FIA-01).

    Never replaces an existing file unless ``replace`` is given, which is for files the user
    chose to overwrite in a save dialog (reports), never for signed documents.
    """
    if not replace and path.exists():
        raise OutputExistsError(f"{path.name} already exists")
    # mkstemp creates the file readable only by its owner; the result should have the
    # permissions any other new file would (or those of the file it replaces).
    mode = path.stat().st_mode & 0o7777 if replace and path.exists() else 0o666 & ~_umask()
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
            return
        os.link(temporary, path)  # fails if path appeared meanwhile: no silent overwrite
    except FileExistsError as exc:
        raise OutputExistsError(f"{path.name} already exists") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
