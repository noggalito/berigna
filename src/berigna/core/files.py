# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Writing files safely: atomically, with fsync, and never over a file unless asked."""

import datetime as dt
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


def write_atomically(
    path: Path, data: bytes, *, replace: bool = False, private: bool = False
) -> None:
    """Write ``data`` to ``path`` with fsync, all or nothing (RNF-FIA-01).

    Never replaces an existing file unless ``replace`` is given, which is for files the user
    chose to overwrite in a save dialog (reports), never for signed documents. ``private``
    files are readable only by their owner (0600), as personal data that berigna keeps.
    """
    if not replace and path.exists():
        raise OutputExistsError(f"{path.name} already exists")
    # mkstemp creates the file readable only by its owner; the result should have the
    # permissions any other new file would (or those of the file it replaces).
    if private:
        mode = 0o600
    elif replace and path.exists():
        mode = path.stat().st_mode & 0o7777
    else:
        mode = 0o666 & ~_umask()
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


def data_directory() -> Path:
    """berigna's data folder, ``$XDG_DATA_HOME/berigna`` (usually ``~/.local/share/berigna``).

    Read from the environment on every call; GLib.get_user_data_dir() keeps the first answer
    for the whole process, so the tests could not move it and wrote into the user's own
    history (2026-10-29)."""
    data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data) / "berigna"


def dated_name(name: str, moment: dt.datetime | None = None) -> str:
    """``name`` after the local date and time, so that exports sort by when they were made:
    "2026-10-29_00h55_historial-berigna.csv" (decision of 2026-10-29)."""
    local = (moment or dt.datetime.now()).astimezone()
    return f"{local:%Y-%m-%d_%Hh%M}_{name}"
