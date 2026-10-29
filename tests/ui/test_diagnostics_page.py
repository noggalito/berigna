# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Diagnosis page (CU-07, RF-007)."""

from collections.abc import Generator
from pathlib import Path

from berigna.core.diagnostics import Status, Step
from berigna.core.token.monitor import DeviceState, DeviceStatus
from berigna.ui.application import BerignaApplication
from berigna.ui.diagnostics import DiagnosticsPage, system_description
from conftest import drive, wait_until


def test_system_description(tmp_path: Path) -> None:
    release = tmp_path / "os-release"
    release.write_text('NAME="Debian GNU/Linux"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n')
    assert system_description(release).startswith("Debian GNU/Linux 13 (trixie) · Python 3.")
    assert system_description(tmp_path / "no-existe").startswith("Linux · Python")


def test_diagnosis_from_the_menu(app: BerignaApplication) -> None:
    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        window = app.main_window
        assert window is not None
        window.show_device_status(
            DeviceStatus(DeviceState.DNIE_READY, ("innovatech 00",), "innovatech 00", b"\x3b")
        )
        app.activate_action("diagnostics", None)
        yield from wait_until(lambda: window.diagnostics is not None)
        page: DiagnosticsPage = window.diagnostics  # type: ignore[assignment]
        yield from wait_until(lambda: page.results is not None, 15)
        assert page.results is not None
        statuses = {result.step: result.status for result in page.results}
        assert statuses[Step.PCSC] is Status.OK
        assert statuses[Step.CARD] is Status.OK
        assert statuses[Step.CERTIFICATE] is Status.OK  # the simulated card, without PIN
        assert statuses[Step.TSA] is Status.SKIPPED  # no TSA in the tests (DP-02)
        report = page.report()
        assert "[✓] DNIe: Hay un DNIe en innovatech 00." in report
        assert "****4321" in report
        assert "87654321" not in report
        row, _icon = page._rows[Step.CARD]
        assert row.get_subtitle() == "Hay un DNIe en innovatech 00."
        row, _icon = page._rows[Step.VALIDATION]
        assert "berigna está funcionando sin acceso a la red" in row.get_subtitle()
        page.run()  # check again
        yield from wait_until(lambda: page._again.get_sensitive(), 15)

    drive(app, script)
