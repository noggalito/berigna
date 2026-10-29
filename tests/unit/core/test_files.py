# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Writing files safely (RNF-FIA-01, RF-045)."""

import os
import stat
from pathlib import Path

import pytest

from berigna.core.errors import OutputExistsError
from berigna.core.files import _umask, write_atomically


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_new_files_get_the_usual_permissions(tmp_path: Path) -> None:
    """Signed files were left readable only by their owner (mkstemp's 0600), 2026-10-29."""
    path = tmp_path / "firmado.pdf"
    write_atomically(path, b"datos")
    assert path.read_bytes() == b"datos"
    assert _mode(path) == 0o666 & ~_umask()
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_replacing_keeps_the_permissions(tmp_path: Path) -> None:
    path = tmp_path / "informe.csv"
    path.write_bytes(b"antes")
    os.chmod(path, 0o640)
    write_atomically(path, b"despues", replace=True)
    assert path.read_bytes() == b"despues"
    assert _mode(path) == 0o640


def test_never_overwrites_unless_asked(tmp_path: Path) -> None:
    path = tmp_path / "firmado.pdf"
    path.write_bytes(b"original")
    with pytest.raises(OutputExistsError):
        write_atomically(path, b"otro")
    assert path.read_bytes() == b"original"


def test_umask(tmp_path: Path) -> None:
    status = tmp_path / "status"
    status.write_text("Name:\tberigna\nUmask:\t0077\n")
    assert _umask(status) == 0o077
    assert _umask(tmp_path / "no-existe") == 0o022
    status.write_text("Name:\tberigna\n")
    assert _umask(status) == 0o022
