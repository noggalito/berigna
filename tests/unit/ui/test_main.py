# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Entry point: a broken installation is reported in one line, not with a traceback."""

from pathlib import Path

import pytest

from berigna.main import main


def test_missing_resources_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("BERIGNA_RESOURCES", raising=False)
    assert main([]) == 1
    assert "BERIGNA_RESOURCES is not set" in capsys.readouterr().err
    monkeypatch.setenv("BERIGNA_RESOURCES", str(tmp_path / "no-existe.gresource"))
    assert main([]) == 1
    assert "cannot load" in capsys.readouterr().err
