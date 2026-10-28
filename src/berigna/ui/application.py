# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""The GApplication: settings, language, DNIe monitor and the main window."""

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402
from pyhanko.sign.timestamps import TimeStamper  # noqa: E402

from berigna import __version__  # noqa: E402
from berigna.core.errors import TsaError  # noqa: E402
from berigna.core.i18n import Language  # noqa: E402
from berigna.core.net.tsa import TsaSettings, http_timestamper  # noqa: E402
from berigna.core.token.base import TokenSigner  # noqa: E402
from berigna.core.token.dnie_v2 import DnieV2Token, is_dnie_v2  # noqa: E402
from berigna.core.token.monitor import (  # noqa: E402
    DeviceMonitor,
    DeviceStatus,
    PcscStatusSource,
    StatusSource,
)
from berigna.core.token.transport import PcscTransport  # noqa: E402
from berigna.core.trust import TrustStore  # noqa: E402
from berigna.core.validation import PdfVerification, verify_pdf  # noqa: E402
from berigna.ui.i18n import _, choose_language, set_language  # noqa: E402
from berigna.ui.signing import SigningServices  # noqa: E402
from berigna.ui.window import MainWindow  # noqa: E402

APPLICATION_ID = "pe.berigna.Berigna"


def _open_dnie() -> TokenSigner:
    """An exclusive session with the first reader holding a DNIe v2 (ADR-0012)."""
    return DnieV2Token(PcscTransport.open_first(is_dnie_v2))


WEBSITE = "https://github.com/noggalito/berigna"


class BerignaApplication(Adw.Application):
    def __init__(
        self,
        *,
        status_source: Callable[[], StatusSource] = PcscStatusSource,
        trust_store: Callable[[], TrustStore] = TrustStore.load_bundled,
        open_token: Callable[[], TokenSigner] | None = None,
        timestamper: Callable[[], TimeStamper | None] | None = None,
        online: bool = True,
        unique: bool = True,
    ) -> None:
        flags = Gio.ApplicationFlags.HANDLES_OPEN
        if not unique:
            flags |= Gio.ApplicationFlags.NON_UNIQUE
        super().__init__(application_id=APPLICATION_ID, flags=flags)
        self._status_source = status_source
        self._trust_store = trust_store
        self._open_token = open_token or _open_dnie
        self._timestamper = timestamper or self._configured_timestamper
        self._online = online
        self._monitor: DeviceMonitor | None = None
        self._device_status: DeviceStatus | None = None
        self.main_window: MainWindow | None = None
        self.settings: Gio.Settings | None = None

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self.settings = Gio.Settings.new(APPLICATION_ID)
        set_language(choose_language(self.settings.get_string("ui-language")))
        self.settings.connect("changed::ui-language", self._on_language_changed)
        for name, callback, accels in (
            ("about", self._show_about, []),
            ("quit", lambda *_args: self.quit(), ["<Control>q"]),
            ("show-in-spanish", self._show_in_spanish, []),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)
            self.set_accels_for_action(f"app.{name}", accels)
        self.set_accels_for_action("win.open", ["<Control>o"])
        self._monitor = DeviceMonitor(self._status_source(), self._on_device_status)
        self._monitor.start()

    def do_shutdown(self) -> None:
        if self._monitor is not None:
            self._monitor.stop()
        Adw.Application.do_shutdown(self)

    def do_activate(self) -> None:
        self._window().window.present()

    def do_open(self, files: list[Gio.File], _n_files: int, _hint: str) -> None:
        window = self._window()
        window.window.present()
        if files:  # batches come with increment 6; for now the first file is opened
            window.open_file(files[0])

    def _window(self) -> MainWindow:
        if self.main_window is None:
            services = SigningServices(
                open_token=self._open_token,
                trust_store=self._trust_store,
                timestamper=self._timestamper,
                settings=self.settings,
                online=self._online,
            )
            self.main_window = MainWindow(self, self.verify, services)
            self.main_window.show_device_status(self._device_status)
        return self.main_window

    def verify(self, data: bytes) -> tuple[PdfVerification, TrustStore]:
        """Verify a PDF now, online unless disabled (called from a worker thread)."""
        store = self._trust_store()
        timeout = float(self.settings.get_uint("network-timeout")) if self.settings else 10.0
        return verify_pdf(data, store, online=self._online, timeout=timeout), store

    def _configured_timestamper(self) -> TimeStamper | None:
        """The TSA of the preferences (``tsa-url``); none until one is configured (DP-02)."""
        if self.settings is None or not self.settings.get_string("tsa-url"):
            return None
        settings = TsaSettings(
            self.settings.get_string("tsa-url"),
            timeout=float(self.settings.get_uint("network-timeout")),
        )
        try:
            return http_timestamper(settings)
        except TsaError:
            return None

    def _on_device_status(self, status: DeviceStatus) -> None:
        """Called from the monitor thread."""

        def show() -> bool:
            self._device_status = status
            if self.main_window is not None:
                self.main_window.show_device_status(status)
            return GLib.SOURCE_REMOVE

        GLib.idle_add(show)

    def _on_language_changed(self, settings: Gio.Settings, key: str) -> None:
        set_language(choose_language(settings.get_string(key)))
        old = self.main_window
        if old is None:
            return
        self.main_window = None
        window = self._window()
        if old.document is not None:
            window.open_file(Gio.File.new_for_path(str(old.document.path)))
        window.window.present()
        old.window.destroy()

    def _show_in_spanish(self, *_args: Any) -> None:
        if self.settings is not None:
            self.settings.set_string("ui-language", Language.ES_PE.value)

    def _show_about(self, *_args: Any) -> None:
        about = Adw.AboutDialog(
            application_name="berigna",
            application_icon=APPLICATION_ID,
            version=__version__,
            comments=_("Sign and verify documents with your Peruvian DNIe."),
            developer_name="Calú",
            copyright="© 2026 Calú",
            license_type=Gtk.License.GPL_3_0,
            website=WEBSITE,
            issue_url=f"{WEBSITE}/issues",
        )
        parent = self.main_window.window if self.main_window else None
        about.present(parent)
