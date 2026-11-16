# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Writing files safely (RNF-FIA-01, RF-045)."""

import datetime as dt
import errno
import os
import stat
from pathlib import Path

import pytest

from berigna.core import files
from berigna.core.errors import OutputExistsError
from berigna.core.files import (
    _rename_noreplace,
    _umask,
    data_directory,
    dated_name,
    write_atomically,
)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_new_files_get_the_usual_permissions(tmp_path: Path) -> None:
    """Signed files were left readable only by their owner (mkstemp's 0600), 2026-10-29."""
    path = tmp_path / "firmado.pdf"
    write_atomically(path, b"datos")
    assert path.read_bytes() == b"datos"
    assert _mode(path) == 0o666 & ~_umask()
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def _no_hardlinks(*_args: object, **_kwargs: object) -> None:
    raise OSError(errno.EPERM, "operation not permitted")


def _fake_rename(source: Path, target: Path) -> None:
    if target.exists():
        raise FileExistsError(errno.EEXIST, "already exists", target)
    os.rename(source, target)


def test_a_filesystem_without_hardlinks_publishes_with_renameat2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FAT/exFAT memories and some network mounts cannot hardlink (PR #88)."""
    monkeypatch.setattr(os, "link", _no_hardlinks)
    monkeypatch.setattr(files, "_rename_noreplace", _fake_rename)
    path = tmp_path / "firmado.pdf"
    write_atomically(path, b"datos")
    assert path.read_bytes() == b"datos"
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]

    with pytest.raises(OutputExistsError):
        write_atomically(path, b"otro")
    assert path.read_bytes() == b"datos"


@pytest.mark.parametrize("error", [errno.EINVAL, errno.ENOSYS])
def test_the_exclusive_copy_is_the_last_resort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    """Only an unavailable renameat2 falls back to a copy, with its known risk (PR #88)."""

    def unavailable(*_args: object) -> None:
        raise OSError(error, "renameat2 is not available")

    monkeypatch.setattr(os, "link", _no_hardlinks)
    monkeypatch.setattr(files, "_rename_noreplace", unavailable)
    path = tmp_path / "firmado.pdf"
    write_atomically(path, b"datos")
    assert path.read_bytes() == b"datos"
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]

    with pytest.raises(OutputExistsError):
        write_atomically(path, b"otro")
    assert path.read_bytes() == b"datos"


def test_renameat2_eeexist_is_an_output_exists_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """renameat2's EEXIST must never overwrite the file that appeared meanwhile (PR #88)."""

    def exists(*_args: object) -> None:
        raise FileExistsError(errno.EEXIST, "already exists")

    monkeypatch.setattr(os, "link", _no_hardlinks)
    monkeypatch.setattr(files, "_rename_noreplace", exists)
    path = tmp_path / "firmado.pdf"
    path.write_bytes(b"original")
    with pytest.raises(OutputExistsError):
        write_atomically(path, b"otro")
    assert path.read_bytes() == b"original"


def test_renameat2_is_atomic_on_this_filesystem(tmp_path: Path) -> None:
    """The real libc call: the first rename publishes, the second fails with EEXIST."""
    source = tmp_path / "temporal"
    target = tmp_path / "firmado.pdf"
    source.write_bytes(b"datos")
    try:
        _rename_noreplace(source, target)
    except OSError as exc:
        if exc.errno in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
            pytest.skip(f"this filesystem does not support renameat2: {exc}")
        raise
    assert target.read_bytes() == b"datos"
    assert not source.exists()

    source.write_bytes(b"otro")
    with pytest.raises(FileExistsError):
        _rename_noreplace(source, target)
    assert target.read_bytes() == b"datos"


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


def test_data_directory_follows_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert data_directory() == tmp_path / "berigna"
    monkeypatch.delenv("XDG_DATA_HOME")
    assert data_directory() == Path.home() / ".local" / "share" / "berigna"


def test_dated_name() -> None:
    lima = dt.timezone(dt.timedelta(hours=-5))
    moment = dt.datetime(2026, 10, 29, 5, 55, tzinfo=dt.UTC)
    name = dated_name("historial-berigna.csv", moment)
    assert name == f"{moment.astimezone():%Y-%m-%d_%Hh%M}_historial-berigna.csv"
    assert dated_name("x.csv", dt.datetime(2026, 10, 29, 0, 55, tzinfo=lima)).endswith("_x.csv")
    assert dated_name("x.csv")[:4].isdigit()


def test_private_files_are_for_their_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "rubrica.png"
    path.write_bytes(b"antes")
    os.chmod(path, 0o664)
    write_atomically(path, b"imagen", replace=True, private=True)
    assert _mode(path) == 0o600
