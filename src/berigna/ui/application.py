# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The GApplication: settings, language, DNIe monitor and the main window."""

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402
from pyhanko.sign.timestamps import TimeStamper  # noqa: E402

from berigna import __version__  # noqa: E402
from berigna.core.errors import TsaError  # noqa: E402
from berigna.core.i18n import Language  # noqa: E402
from berigna.core.net.proxy import ProxyMode, apply_proxy  # noqa: E402
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
from berigna.core.trust.cache import Download, TslCache, TslRefresh, refresh  # noqa: E402
from berigna.core.trust.tsl import extend_store  # noqa: E402
from berigna.core.validation import PdfVerification, verify_pdf  # noqa: E402
from berigna.ui.i18n import _, choose_language, set_language  # noqa: E402
from berigna.ui.preferences import PreferencesDialog  # noqa: E402
from berigna.ui.signing import SigningServices  # noqa: E402
from berigna.ui.window import MainWindow  # noqa: E402

APPLICATION_ID = "com.noggalito.Berigna"
# Where a proxy of the desktop is looked up: the services berigna talks to are all on the
# Internet, and GIO answers per URL (a PAC file may say otherwise for intranet hosts).
PROXY_PROBE_URL = "https://iofe.indecopi.gob.pe/"

log = logging.getLogger(__name__)


def _open_dnie() -> TokenSigner:
    """An exclusive session with the first reader holding a DNIe v2 (ADR-0012)."""
    return DnieV2Token(PcscTransport.open_first(is_dnie_v2))


WEBSITE = "https://berigna.noggalito.com"
REPOSITORY = "https://github.com/noggalito/berigna"


class BerignaApplication(Adw.Application):
    def __init__(
        self,
        *,
        status_source: Callable[[], StatusSource] = PcscStatusSource,
        trust_store: Callable[[], TrustStore] | None = None,
        open_token: Callable[[], TokenSigner] | None = None,
        timestamper: Callable[[], TimeStamper | None] | None = None,
        tsl_cache: TslCache | None = None,
        tsl_download: Download | None = None,
        appearance_dir: Path | None = None,
        online: bool = True,
        unique: bool = True,
    ) -> None:
        """Without ``trust_store``, the bundled store is extended with the INDECOPI trusted
        list, refreshed in the background at startup (ADR-0014)."""
        flags = Gio.ApplicationFlags.HANDLES_OPEN
        if not unique:
            flags |= Gio.ApplicationFlags.NON_UNIQUE
        super().__init__(application_id=APPLICATION_ID, flags=flags)
        self._status_source = status_source
        self._trust_store = trust_store or self._default_store
        self._uses_tsl = trust_store is None
        self._tsl_cache = tsl_cache
        self._tsl_download = tsl_download
        self._appearance_dir = appearance_dir
        self.tsl: TslRefresh | None = None
        self.preferences: PreferencesDialog | None = None
        self._open_token = open_token or _open_dnie
        self._timestamper = timestamper or self._configured_timestamper
        self._online = online
        self._monitor: DeviceMonitor | None = None
        self._device_status: DeviceStatus | None = None
        self.main_window: MainWindow | None = None
        self.settings: Gio.Settings | None = None

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        Gtk.Window.set_default_icon_name(APPLICATION_ID)
        self.settings = Gio.Settings.new(APPLICATION_ID)
        set_language(choose_language(self.settings.get_string("ui-language")))
        self.settings.connect("changed::ui-language", self._on_language_changed)
        for key in ("proxy-mode", "proxy-url"):
            self.settings.connect(f"changed::{key}", lambda *_args: self.apply_proxy())
        self.apply_proxy()
        for name, callback, accels in (
            ("about", self._show_about, []),
            ("preferences", lambda *_args: self.show_preferences(), ["<Control>comma"]),
            ("diagnostics", lambda *_args: self.show_diagnostics(), []),
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
        if self._uses_tsl:
            self.refresh_tsl()

    def do_shutdown(self) -> None:
        if self._monitor is not None:
            self._monitor.stop()
        Adw.Application.do_shutdown(self)

    def do_activate(self) -> None:
        self._window().window.present()

    def do_open(self, files: list[Gio.File], _n_files: int, _hint: str) -> None:
        window = self._window()
        window.window.present()
        if files:
            window.open_files(files)

    def _window(self) -> MainWindow:
        if self.main_window is None:
            services = SigningServices(
                open_token=self._open_token,
                trust_store=self._trust_store,
                timestamper=self._timestamper,
                settings=self.settings,
                online=self._online,
                appearance_dir=self.appearance_dir(),
            )
            self.main_window = MainWindow(self, self.verify, services)
            self.main_window.show_device_status(self._device_status)
        return self.main_window

    # -- Trust store and trusted list (RF-061, ADR-0014) ----------------------------------------

    def appearance_dir(self) -> Path:
        """Where the preloaded rubric and logo are kept (RF-012)."""
        if self._appearance_dir is None:
            self._appearance_dir = Path(GLib.get_user_data_dir()) / "berigna" / "apariencia"
        return self._appearance_dir

    def tsl_cache(self) -> TslCache:
        if self._tsl_cache is None:
            self._tsl_cache = TslCache(Path(GLib.get_user_data_dir()) / "berigna" / "tsl")
        return self._tsl_cache

    def _default_store(self) -> TrustStore:
        """The bundled store, plus the CAs of the trusted list once it is available."""
        store = TrustStore.load_bundled()
        if self.tsl is not None and self.tsl.trusted_list is not None:
            store = extend_store(store, self.tsl.trusted_list)
        return store

    def refresh_tsl(
        self, *, force: bool = False, on_done: Callable[[TslRefresh], None] | None = None
    ) -> None:
        """Refresh the trusted list in a worker thread; ``on_done`` runs in the main loop."""
        cache = self.tsl_cache()
        download = self._tsl_download

        def work() -> None:
            result = refresh(cache, download=download, force=force)
            if result.error is not None:
                log.warning("trusted list not updated: %s", result.error)

            def done() -> bool:
                self.tsl = result
                if on_done is not None:
                    on_done(result)
                return GLib.SOURCE_REMOVE

            GLib.idle_add(done)

        threading.Thread(target=work, name="berigna-tsl", daemon=True).start()

    # -- Network (RF-064) ---------------------------------------------------------------------

    def apply_proxy(self) -> None:
        """Apply the proxy of the preferences to every HTTP request of the process."""
        if self.settings is None:
            return
        mode = ProxyMode(self.settings.get_string("proxy-mode"))
        system = None
        if mode is ProxyMode.SYSTEM:
            try:
                found = Gio.ProxyResolver.get_default().lookup(PROXY_PROBE_URL, None)
                system = next((url for url in found if url != "direct://"), None)
            except GLib.Error as exc:
                log.warning("cannot ask the desktop for a proxy: %s", exc.message)
        try:
            apply_proxy(mode, manual_url=self.settings.get_string("proxy-url"), system_url=system)
        except ValueError:
            log.warning("invalid manual proxy URL; using the proxy of the system")
            apply_proxy(ProxyMode.SYSTEM, system_url=system)

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

    def show_diagnostics(self) -> None:
        window = self._window()
        window.window.present()
        window.show_diagnostics()

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
        reopen = self.preferences is not None
        old.window.destroy()
        if reopen:  # the dialog went with the old window: show it again, in the new language
            self.show_preferences()

    def show_preferences(self) -> None:
        window = self._window()
        self.preferences = PreferencesDialog(self)
        self.preferences.connect("closed", lambda _d: setattr(self, "preferences", None))
        self.preferences.present(window.window)

    def _show_in_spanish(self, *_args: Any) -> None:
        if self.settings is not None:
            self.settings.set_string("ui-language", Language.ES_PE.value)

    def _show_about(self, *_args: Any) -> None:
        about = Adw.AboutDialog(
            application_name="berigna",
            application_icon=APPLICATION_ID,
            version=__version__,
            comments=_("Sign and verify documents with your Peruvian DNIe."),
            developer_name="noggalito",
            copyright="© 2026 noggalito",
            license_type=Gtk.License.GPL_3_0,
            website=WEBSITE,
            issue_url=f"{REPOSITORY}/issues",
        )
        parent = self.main_window.window if self.main_window else None
        about.present(parent)
