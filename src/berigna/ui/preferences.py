# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Preferences (CU-08; RF-061 to RF-064, RF-080): general, network and trust.

Every value lives in GSettings (`com.noggalito.Berigna`), so an administrator can set defaults
and lock keys for a whole organisation with dconf (configuracion-y-datos §2).
"""

import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402
from pyhanko.sign.timestamps import TimeStamper  # noqa: E402

from berigna.core.appearance import (  # noqa: E402
    AppearanceKind,
    remove_image,
    store_image,
    stored_image,
)
from berigna.core.errors import AppearanceError, BerignaError  # noqa: E402
from berigna.core.net.proxy import ProxyMode, valid_proxy_url  # noqa: E402
from berigna.core.net.tsa import probe  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.trust.cache import TslRefresh  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.help import HelpTopic, help_button  # noqa: E402
from berigna.ui.i18n import _, catalogue  # noqa: E402
from berigna.ui.signing import APPEARANCES, DNI_OPTIONS, LEVEL_ORDER  # noqa: E402
from berigna.ui.widgets import brand_markup, label_factory  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.application import BerignaApplication

# Each language written in its own language (ADR-0015 §6); "system" is translated.
LANGUAGES = (("system", None), ("es_PE", "Español (Perú)"), ("quz_PE", "Runasimi (quechua)"))
DIGESTS = (("sha256", "SHA-256"), ("sha384", "SHA-384"), ("sha512", "SHA-512"))


class PreferencesDialog(Adw.PreferencesDialog):
    def __init__(self, application: "BerignaApplication") -> None:
        super().__init__(search_enabled=False, content_width=720)
        self._app = application
        settings = application.settings
        if settings is None:
            raise RuntimeError("preferences need the settings of the application")
        self._settings: Gio.Settings = settings
        self._general_page = self._general()
        self._network_page = self._network()
        self._trust_page = self._trust()
        self._visible_page = self._visible()
        pages = (self._general_page, self._visible_page, self._network_page, self._trust_page)
        for page in pages:
            self.add(page)

    # -- Helpers -------------------------------------------------------------------------------

    def _combo(
        self,
        title: str,
        key: str,
        options: Sequence[tuple[str, str]],
        get: Callable[[], str] | None = None,
        put: Callable[[str], None] | None = None,
    ) -> Adw.ComboRow:
        """A combo row bound to a string or enum key: ``options`` are (value, label) pairs.
        ``get`` and ``put`` replace reading and writing the key, for a row over two keys."""
        get = get or (lambda: self._settings.get_string(key))
        put = put or (lambda value: self._settings.set_string(key, value))
        values = [value for value, _label in options]
        labels = [label for _value, label in options]
        # The chosen value goes under the title, where it has the whole width: on the right it
        # was cut ("Validación a largo plazo (…"), and so were the items of the list. The
        # subtitle is set here, because AdwComboRow (use-subtitle) leaves it empty until the
        # selection first changes.
        row = Adw.ComboRow(
            title=title,
            model=Gtk.StringList.new(labels),
            factory=label_factory(visible=False),
            list_factory=label_factory(visible=True),
            subtitle_lines=0,
        )
        current = get()
        row.set_selected(values.index(current) if current in values else 0)
        row.set_subtitle(labels[row.get_selected()])

        def changed(row: Adw.ComboRow, _param: object) -> None:
            row.set_subtitle(labels[row.get_selected()])
            value = values[row.get_selected()]
            if get() != value:
                put(value)

        row.connect("notify::selected", changed)
        return row

    def _entry(self, title: str, key: str) -> Adw.EntryRow:
        row = Adw.EntryRow(title=title, show_apply_button=True, use_markup=False)
        row.set_text(self._settings.get_string(key))
        return row

    def toast(self, message: str) -> None:
        self.add_toast(Adw.Toast.new(brand_markup(message)))

    # -- General -------------------------------------------------------------------------------

    def _general(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title=_("General"), icon_name="preferences-system-symbolic")
        language = Adw.PreferencesGroup(title=_("Language"))
        self.language = self._combo(
            _("Interface Language"),
            "ui-language",
            [(value, label or _("Use the System Language")) for value, label in LANGUAGES],
        )
        language.add(self.language)
        page.add(language)

        signing = Adw.PreferencesGroup(title=_("Signatures"))
        self.level = self._combo(
            _("Default Level"),
            "default-level",
            [(level.value, presentation.level_title(level)) for level in LEVEL_ORDER],
        )
        self.level.add_suffix(help_button(HelpTopic.SIGNATURE_LEVELS))
        self.digest = self._combo(_("Hash Algorithm"), "digest-algorithm", DIGESTS)
        self.digest.add_suffix(help_button(HelpTopic.HASH_ALGORITHM))
        self.suffix = self._entry(_("Suffix of Signed Files"), "output-suffix")
        self.suffix.connect("apply", self._on_suffix)
        self.folder = Adw.ActionRow(title=_("Folder for Signed Files"), use_markup=False)
        choose = Gtk.Button(
            icon_name="folder-open-symbolic",
            tooltip_text=_("Choose Folder"),
            valign=Gtk.Align.CENTER,
        )
        choose.add_css_class("flat")
        choose.connect("clicked", lambda _b: self._choose_folder())
        self.folder_reset = Gtk.Button(
            icon_name="edit-clear-symbolic",
            tooltip_text=_("Use the Folder of the Original"),
            valign=Gtk.Align.CENTER,
        )
        self.folder_reset.add_css_class("flat")
        self.folder_reset.connect("clicked", lambda _b: self.set_folder(""))
        self.folder.add_suffix(choose)
        self.folder.add_suffix(self.folder_reset)
        self._show_folder()
        for row in (self.level, self.digest, self.suffix, self.folder):
            signing.add(row)
        page.add(signing)
        return page

    def _on_suffix(self, row: Adw.EntryRow) -> None:
        text = row.get_text().strip()
        if not text or "/" in text:
            row.set_text(self._settings.get_string("output-suffix"))
            self.toast(_("The suffix cannot be empty or contain “/”."))
            return
        self._settings.set_string("output-suffix", text)

    def _show_folder(self) -> None:
        folder = self._settings.get_string("output-directory")
        self.folder.set_subtitle(folder or _("The same folder as the original"))
        self.folder_reset.set_visible(bool(folder))

    def set_folder(self, folder: str) -> None:
        self._settings.set_string("output-directory", folder)
        self._show_folder()

    def _choose_folder(self) -> None:
        dialog = Gtk.FileDialog(title=_("Folder for Signed Files"))

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                folder = dialog.select_folder_finish(result)
            except GLib.Error:  # dismissed by the user
                return
            if folder.get_path():
                self.set_folder(str(folder.get_path()))

        dialog.select_folder(self.get_root(), None, chosen)

    # -- Visible signature (RF-012, RF-092) ------------------------------------------------------

    def _visible(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title=_("Visible Signature"), icon_name="document-edit-symbolic")
        defaults = Adw.PreferencesGroup(
            title=_("Defaults"),
            description=_(
                "The signed PDF always carries the full DNI in its certificate; "
                "“DNI in the Signature” only changes what is printed."
            ),
        )

        # One list over two keys: "Not visible" is visible-signature off.
        def get_appearance() -> str:
            if not self._settings.get_boolean("visible-signature"):
                return "none"
            return self._settings.get_string("appearance-kind")

        def put_appearance(value: str) -> None:
            self._settings.set_boolean("visible-signature", value != "none")
            if value != "none":
                self._settings.set_string("appearance-kind", value)

        self.appearance = self._combo(
            _("Appearance"),
            "appearance-kind",
            [(k.value if k else "none", _(label)) for k, label in APPEARANCES],
            get_appearance,
            put_appearance,
        )
        self.stamp_language = self._combo(
            _("Language of the Signature"),
            "appearance-language",
            [(value, label) for value, label in LANGUAGES if label is not None],
        )
        self.dni = self._combo(
            _("DNI in the Signature"),
            "appearance-dni",
            [(display.value, _(label)) for display, label in DNI_OPTIONS],
        )
        for row in (self.appearance, self.stamp_language, self.dni):
            defaults.add(row)
        page.add(defaults)

        images = Adw.PreferencesGroup(
            title=_("Images"),
            description=brand_markup(
                _("Loaded once and kept by berigna, without the metadata of the original file.")
            ),
        )
        self.image_rows: dict[AppearanceKind, tuple[Adw.ActionRow, Gtk.Button]] = {}
        for kind, title in (
            (AppearanceKind.RUBRIC, _("Handwritten Signature")),
            (AppearanceKind.LOGO, _("Logo")),
        ):
            row = Adw.ActionRow(title=title, use_markup=False)
            choose = Gtk.Button(
                icon_name="document-open-symbolic",
                tooltip_text=_("Choose Image"),
                valign=Gtk.Align.CENTER,
            )
            choose.add_css_class("flat")
            choose.connect("clicked", lambda _b, k=kind: self._choose_image(k))
            remove = Gtk.Button(
                icon_name="edit-clear-symbolic",
                tooltip_text=_("Remove Image"),
                valign=Gtk.Align.CENTER,
            )
            remove.add_css_class("flat")
            remove.connect("clicked", lambda _b, k=kind: self.remove_image(k))
            row.add_suffix(choose)
            row.add_suffix(remove)
            self.image_rows[kind] = (row, remove)
            images.add(row)
            self._show_image(kind)
        page.add(images)
        return page

    def _show_image(self, kind: AppearanceKind) -> None:
        row, remove = self.image_rows[kind]
        has = stored_image(self._app.appearance_dir(), kind) is not None
        row.set_subtitle(_("Loaded") if has else _("No image"))
        remove.set_visible(has)

    def set_image(self, kind: AppearanceKind, source: Path) -> None:
        try:
            store_image(self._app.appearance_dir(), kind, source)
        except AppearanceError as exc:
            self.toast(explain_error(exc.code, catalogue()) or "")
        except OSError:
            self.toast(_("{name} could not be saved.").format(name=source.name))
        self._show_image(kind)

    def remove_image(self, kind: AppearanceKind) -> None:
        remove_image(self._app.appearance_dir(), kind)
        self._show_image(kind)

    def _choose_image(self, kind: AppearanceKind) -> None:
        images = Gtk.FileFilter()
        images.set_name(_("Images"))
        for mime in ("image/png", "image/jpeg"):
            images.add_mime_type(mime)
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(images)
        dialog = Gtk.FileDialog(title=_("Choose Image"), filters=filters, default_filter=images)

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                file = dialog.open_finish(result)
            except GLib.Error:  # dismissed by the user
                return
            if file.get_path():
                self.set_image(kind, Path(file.get_path()))

        dialog.open(self.get_root(), None, chosen)

    # -- Network -------------------------------------------------------------------------------

    def _network(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title=_("Network"), icon_name="network-server-symbolic")
        tsa = Adw.PreferencesGroup(
            header_suffix=help_button(HelpTopic.TIMESTAMPING_AUTHORITY),
            title=_("Timestamping Authority"),
            description=_(
                "Needed for the levels with a timestamp. Use a timestamping authority "
                "accredited by INDECOPI."
            ),
        )
        self.tsa_url = self._entry(_("Address of the Timestamping Authority"), "tsa-url")
        self.tsa_url.connect("apply", self._on_tsa_url)
        self.tsa_test = Gtk.Button(label=_("_Test"), use_underline=True, valign=Gtk.Align.CENTER)
        self.tsa_test.connect("clicked", lambda _b: self.test_tsa())
        self.tsa_url.add_suffix(self.tsa_test)
        tsa.add(self.tsa_url)
        page.add(tsa)

        connection = Adw.PreferencesGroup(title=_("Connection"))
        self.timeout = Adw.SpinRow.new_with_range(1, 300, 1)
        self.timeout.set_title(_("Network Timeout"))
        self.timeout.set_subtitle(_("Seconds to wait for each answer"))
        self.timeout.add_suffix(help_button(HelpTopic.NETWORK_TIMEOUT))
        self._settings.bind("network-timeout", self.timeout, "value", Gio.SettingsBindFlags.DEFAULT)
        self.proxy = self._combo(
            _("Proxy"),
            "proxy-mode",
            [
                (ProxyMode.SYSTEM.value, _("The Proxy of the System")),
                (ProxyMode.MANUAL.value, _("Manual")),
                (ProxyMode.NONE.value, _("No Proxy")),
            ],
        )
        self.proxy.add_suffix(help_button(HelpTopic.PROXY))
        self.proxy_url = self._entry(_("Proxy Address"), "proxy-url")
        self.proxy_url.connect("apply", self._on_proxy_url)
        self.proxy.connect("notify::selected", lambda *_a: self._show_proxy())
        self._show_proxy()
        for row in (self.timeout, self.proxy, self.proxy_url):
            connection.add(row)
        page.add(connection)
        return page

    def _on_tsa_url(self, row: Adw.EntryRow) -> None:
        url = row.get_text().strip()
        if url and not url.startswith(("http://", "https://")):
            row.set_text(self._settings.get_string("tsa-url"))
            self.toast(_("The address must start with http:// or https://."))
            return
        self._settings.set_string("tsa-url", url)

    def test_tsa(self) -> None:
        """Ask the configured TSA for a time-stamp (RF-062, "Test")."""
        configured = self._app._timestamper()
        if configured is None:
            self.toast(_("There is no timestamping authority configured."))
            return
        stamper: TimeStamper = configured
        self.tsa_test.set_sensitive(False)

        def work() -> None:
            try:
                probe(stamper)
                message = _("The timestamping authority answered with a valid time-stamp.")
            except BerignaError as exc:
                message = explain_error(exc.code, catalogue()) or ""

            def done() -> bool:
                self.tsa_test.set_sensitive(True)
                self.toast(message)
                return GLib.SOURCE_REMOVE

            GLib.idle_add(done)

        threading.Thread(target=work, name="berigna-tsa-test", daemon=True).start()

    def _show_proxy(self) -> None:
        manual = self._settings.get_string("proxy-mode") == ProxyMode.MANUAL.value
        self.proxy_url.set_sensitive(manual)

    def _on_proxy_url(self, row: Adw.EntryRow) -> None:
        url = row.get_text().strip()
        if not valid_proxy_url(url):
            row.set_text(self._settings.get_string("proxy-url"))
            self.toast(_("The proxy address must start with http:// or https://."))
            return
        self._settings.set_string("proxy-url", url)

    # -- Trust ---------------------------------------------------------------------------------

    def _trust(self) -> Adw.PreferencesPage:
        page = Adw.PreferencesPage(title=_("Trust"), icon_name="security-high-symbolic")
        tsl = Adw.PreferencesGroup(
            header_suffix=help_button(HelpTopic.TRUSTED_LIST),
            title=_("INDECOPI Trusted List"),
            description=brand_markup(
                _(
                    "berigna adds the certification authorities accredited by INDECOPI to its "
                    "own root certificates. The list is checked once a day."
                )
            ),
        )
        self.tsl_row = Adw.ActionRow(subtitle_lines=0)
        self.tsl_update = Gtk.Button(
            label=_("_Update Now"), use_underline=True, valign=Gtk.Align.CENTER
        )
        self.tsl_update.connect("clicked", lambda _b: self.update_tsl())
        self.tsl_row.add_suffix(self.tsl_update)
        tsl.add(self.tsl_row)
        self.show_tsl(self._app.tsl)
        page.add(tsl)
        return page

    def show_tsl(self, result: TslRefresh | None) -> None:
        title, subtitle = presentation.tsl_status(result)
        self.tsl_row.set_title(brand_markup(title))
        self.tsl_row.set_subtitle(brand_markup(subtitle))

    def update_tsl(self) -> None:
        self.tsl_update.set_sensitive(False)
        self.show_tsl(None)

        def done(result: TslRefresh) -> None:
            self.tsl_update.set_sensitive(True)
            self.show_tsl(result)
            if result.error is not None:
                self.toast(_("The trusted list could not be updated."))
            elif result.downloaded:
                self.toast(_("The trusted list is up to date."))

        self._app.refresh_tsl(force=True, on_done=done)
