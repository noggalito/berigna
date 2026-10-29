# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Diagnosis page (CU-07, RF-007; BRG-UX-001 §3.6).

Opened from the main menu or from a card error. The checks of
:func:`berigna.core.diagnostics.diagnose` run in a worker thread; each one shows its result
and, when something is wrong, what to do. The report can be copied for support, and the
folder of the technical log (RF-083) opened. No PIN is asked.
"""

import platform
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

import berigna  # noqa: E402
from berigna.core.diagnostics import Result, Step, diagnose  # noqa: E402
from berigna.core.logs import log_directory  # noqa: E402
from berigna.core.token.monitor import DeviceStatus  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.i18n import _  # noqa: E402
from berigna.ui.signing import SigningServices  # noqa: E402
from berigna.ui.widgets import brand_markup, named  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow


def system_description(os_release: Path = Path("/etc/os-release")) -> str:
    """The operating system, as /etc/os-release names it, and the Python version."""
    name = platform.system()
    try:
        for line in os_release.read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                name = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return f"{name} · Python {platform.python_version()}"


def offer_failure_report(window: "MainWindow", failure: str, issues: str) -> Adw.AlertDialog:
    """The last run failed unexpectedly (R-DES-11): say so once and offer to copy the
    report. Nothing is sent: the user decides whether to report it, and where."""
    report = presentation.failure_report(failure, berigna.__version__, system_description())
    dialog = Adw.AlertDialog(
        heading=_("berigna Failed Unexpectedly Last Time"),
        body=_(
            "You can copy the report and send it as an issue at {url}. It has no PIN and no "
            "document contents, and the DNI only masked. Nothing is sent on its own."
        ).format(url=issues),
    )
    dialog.add_response("close", _("_Close"))
    dialog.add_response("copy", _("_Copy Report"))
    dialog.set_default_response("copy")

    def respond(_dialog: Adw.AlertDialog, response: str) -> None:
        if response == "copy":
            Gdk.Display.get_default().get_clipboard().set(report)
            window.toast(_("Report copied. It has no PIN, and the DNI only masked."))

    dialog.connect("response", respond)
    dialog.present(window.window)
    return dialog


class DiagnosticsPage:
    def __init__(
        self,
        window: "MainWindow",
        services: SigningServices,
        device_status: Callable[[], DeviceStatus | None],
    ) -> None:
        self._window = window
        self._services = services
        self._device_status = device_status
        self.results: list[Result] | None = None

        self._again = named(
            Gtk.Button(
                icon_name="view-refresh-symbolic", tooltip_text=_("Check Again"), sensitive=False
            )
        )
        self._again.connect("clicked", lambda _b: self.run())

        content = Adw.PreferencesPage()
        self.group = Adw.PreferencesGroup(
            title=_("Diagnosis"),
            description=_(
                "Checks the reader, the DNIe and the services, in order. The PIN is not asked."
            ),
        )
        self._rows: dict[Step, tuple[Adw.ActionRow, Gtk.Image]] = {}
        for step, title in presentation.DIAGNOSIS_TITLES.items():
            row = Adw.ActionRow(title=_(title), subtitle_lines=0)
            icon = Gtk.Image(icon_name="content-loading-symbolic")
            row.add_prefix(icon)
            self.group.add(row)
            self._rows[step] = (row, icon)
        content.add(self.group)

        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER, margin_top=12)
        self._copy = Gtk.Button(label=_("_Copy Report"), use_underline=True, sensitive=False)
        self._copy.connect("clicked", lambda _b: self.copy_report())
        logs = Gtk.Button(label=_("Open the _Log Folder"), use_underline=True)
        logs.connect("clicked", lambda _b: self._open_logs())
        for button in (self._copy, logs):
            button.add_css_class("pill")
            buttons.append(button)
        footer = Adw.PreferencesGroup()
        footer.add(buttons)
        content.add(footer)
        self.page = window.page(_("Diagnosis"), "diagnosis", content, [self._again])
        self.run()

    def run(self) -> None:
        self._again.set_sensitive(False)
        self._copy.set_sensitive(False)
        for row, icon in self._rows.values():
            row.set_subtitle(_("Checking…"))
            icon.set_from_icon_name("content-loading-symbolic")
            for style in ("success", "warning", "error", "dimmed"):
                icon.remove_css_class(style)
        services, status = self._services, self._device_status()

        def work() -> None:
            results = diagnose(
                status,
                open_token=services.open_token,
                store=services.trust_store(),
                timestamper=services.timestamper(),
                online=services.online,
            )
            GLib.idle_add(self.show, results)

        threading.Thread(target=work, name="berigna-diagnosis", daemon=True).start()

    def show(self, results: list[Result]) -> bool:
        self.results = results
        for result in results:
            row, icon = self._rows[result.step]
            name, style = presentation.DIAGNOSIS_ICONS[result.status]
            icon.set_from_icon_name(name)
            icon.add_css_class(style)
            row.set_subtitle(brand_markup(presentation.diagnosis_text(result)))
        self._again.set_sensitive(True)
        self._copy.set_sensitive(True)
        return GLib.SOURCE_REMOVE

    def report(self) -> str:
        return presentation.diagnosis_report(
            self.results or [], berigna.__version__, system_description()
        )

    def copy_report(self) -> None:
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(self.report())
        self._window.toast(_("Report copied. It has no PIN, and the DNI only masked."))

    def _open_logs(self) -> None:
        directory = log_directory()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        launcher = Gtk.FileLauncher(file=Gio.File.new_for_path(str(directory)))
        launcher.launch(self._window.window, None, None)
