# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Signing a PDF (CU-01, CU-03; BRG-UX-001 §3.2 and §3.3).

The core runs in a worker thread (:func:`berigna.core.signing.sign_pdf_file`): it validates the
certificate and probes the TSA before asking for the PIN through a callback. That callback
shows :class:`PinDialog` in the main loop and waits for the user. The PIN is sent once per
explicit confirmation (P-06); after a wrong PIN the user starts again, with the remaining tries
shown (P-07).
"""

import datetime as dt
import hashlib
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402
from pyhanko.sign.timestamps import TimeStamper  # noqa: E402

from berigna.core.appearance import (  # noqa: E402
    AppearanceKind,
    StampData,
    VisibleSignature,
    render_appearance,
    stored_image,
)
from berigna.core.documents import DocumentInfo  # noqa: E402
from berigna.core.errors import (  # noqa: E402
    AppearanceError,
    BerignaError,
    LevelNotAvailableError,
    PinBlockedError,
    PinIncorrectError,
    SigningCancelledError,
)
from berigna.core.formats.pades import PadesOptions, SignatureLevel  # noqa: E402
from berigna.core.i18n import Language, translations  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.signing import SignResult, output_path, sign_pdf_file  # noqa: E402
from berigna.core.token.base import HashAlgorithmName, TokenSigner  # noqa: E402
from berigna.core.token.pin import Pin  # noqa: E402
from berigna.core.trust import TrustStore  # noqa: E402
from berigna.core.validation import SignerCheck  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.help import HelpTopic, help_button  # noqa: E402
from berigna.ui.i18n import N_, _, catalogue, current_language  # noqa: E402
from berigna.ui.preview import PdfPreview  # noqa: E402
from berigna.ui.widgets import label_factory  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow

log = logging.getLogger(__name__)

# Order of the level list: recommended first (BRG-UX-001 §3.2).
LEVEL_ORDER = (SignatureLevel.B_LT, SignatureLevel.B_LTA, SignatureLevel.B_T, SignatureLevel.B_B)


@dataclass(frozen=True)
class SigningServices:
    """What signing needs from the application; tests replace the card and the network."""

    open_token: Callable[[], TokenSigner]
    trust_store: Callable[[], TrustStore]
    timestamper: Callable[[], TimeStamper | None]  # None: no TSA configured (DP-02)
    settings: Gio.Settings | None
    online: bool = True
    appearance_dir: Path | None = None  # preloaded rubric and logo (None: none available)


# Kinds of visible signature, in the order of the list (decision of 2026-10-28).
APPEARANCES = (
    (AppearanceKind.TEXT, N_("Text only")),
    (AppearanceKind.RUBRIC, N_("Handwritten signature (image)")),
    (AppearanceKind.LOGO, N_("Logo")),
    (AppearanceKind.QR, N_("QR code")),
)


class PinDialog(Adw.Dialog):
    """Summary of what is going to be signed and the PIN entry (P-01, P-05, P-07)."""

    def __init__(
        self,
        document: DocumentInfo,
        check: SignerCheck,
        level: SignatureLevel,
        remaining_tries: int | None,
        reply: Callable[[Pin | None], None],
    ) -> None:
        super().__init__(title=_("Confirm Signature"), content_width=420)
        self._reply = reply
        self._answered = False
        self._summary = (document, check, level)

        summary = Adw.PreferencesGroup()
        for detail in presentation.pin_summary(document, check, level):
            row = Adw.ActionRow(title=detail.label, subtitle=detail.value, use_markup=False)
            row.add_css_class("property")
            summary.add(row)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_start(18)
        box.set_margin_end(18)
        box.set_margin_bottom(18)
        box.append(summary)
        for warning in presentation.pin_warnings(check, remaining_tries):
            label = Gtk.Label(label=warning, wrap=True, xalign=0)
            label.add_css_class("warning")
            box.append(label)

        self.entry = Gtk.PasswordEntry(show_peek_icon=True, hexpand=True)
        self.entry.update_property([Gtk.AccessibleProperty.LABEL], [_("DNIe PIN")])
        self.entry.connect("changed", lambda _e: self._update())
        self.entry.connect("activate", lambda _e: self._confirm())
        label = Gtk.Label(label=_("DNIe PIN"), xalign=0)
        label.add_css_class("heading")
        box.append(label)
        box.append(self.entry)

        if current_language() is Language.QUZ_PE:
            spanish = Gtk.Button(label=_("Show in Spanish"), halign=Gtk.Align.START)
            spanish.add_css_class("flat")
            spanish.connect("clicked", lambda _b: self._show_spanish())
            box.append(spanish)

        buttons = Gtk.Box(spacing=12, homogeneous=True, margin_top=6)
        self.cancel_button = Gtk.Button(label=_("_Cancel"), use_underline=True)
        self.sign_button = Gtk.Button(label=_("_Sign"), use_underline=True, sensitive=False)
        self.sign_button.add_css_class("suggested-action")
        self.cancel_button.connect("clicked", lambda _b: self.close())
        self.sign_button.connect("clicked", lambda _b: self._confirm())
        buttons.append(self.cancel_button)
        buttons.append(self.sign_button)
        box.append(buttons)

        view = Adw.ToolbarView(content=box)
        view.add_top_bar(Adw.HeaderBar())
        self.set_child(view)
        self.set_focus(self.entry)
        self.connect("closed", lambda _d: self._answer(None))

    def _update(self) -> None:
        self.sign_button.set_sensitive(bool(self.entry.get_text()))

    def _confirm(self) -> None:
        text = self.entry.get_text()
        if not text:
            return
        pin = Pin(bytearray(text.encode()))
        self.entry.set_text("")  # P-04: the copies GTK and Python keep are out of our hands
        self._answer(pin)
        self.close()

    def _answer(self, pin: Pin | None) -> None:
        if not self._answered:
            self._answered = True
            self._reply(pin)

    def _show_spanish(self) -> None:
        """The summary in Spanish, without changing the language (BRG-UX-001 §4.2)."""
        spanish = translations(Language.ES_PE)
        document, check, level = self._summary
        rows = presentation.pin_summary(document, check, level, spanish)
        dialog = Adw.AlertDialog(
            heading=spanish.gettext("Confirm Signature"),
            body="\n".join(f"{row.label}: {row.value}" for row in rows),
        )
        dialog.add_response("close", spanish.gettext("_Close"))
        dialog.present(self)


class SigningPage:
    """Preview, level and signature data, and the signing flow."""

    def __init__(
        self,
        window: "MainWindow",
        document: DocumentInfo,
        services: SigningServices,
        *,
        existing_problems: bool = False,
    ) -> None:
        self._window = window
        self._services = services
        self.data = document.path.read_bytes()
        # What is signed is what is previewed (RF-018): the hash of these very bytes.
        self.document = DocumentInfo(
            document.path,
            document.kind,
            len(self.data),
            hashlib.sha256(self.data).hexdigest(),
            document.pages,
            document.signatures,
            document.locked,
        )
        self._remaining_tries: int | None = None
        self._level = SignatureLevel.B_B
        self.result: SignResult | None = None
        self.pin_dialog: PinDialog | None = None

        self._sign = Gtk.Button(label=_("_Sign"), use_underline=True)
        self._sign.add_css_class("suggested-action")
        self._sign.connect("clicked", lambda _b: self.start())

        self._stack = Gtk.Stack()
        self._stack.add_named(self._form(existing_problems), "form")
        self._stack.add_named(self._busy(), "busy")
        self.page = window.page(document.path.name, "signing", self._stack, [self._sign])
        self._sign.set_sensitive(not document.locked)

    # -- Form ----------------------------------------------------------------------------------

    def _form(self, existing_problems: bool) -> Gtk.Widget:
        panel = Adw.PreferencesPage(width_request=340, hexpand=False)
        notices = []
        if self.document.locked:
            notices.append(explain_error("ERR-307", catalogue()) or "")
        if existing_problems:
            notices.append(
                _(
                    "Some of the signatures already in this document are not valid. "
                    "Your signature will be added anyway."
                )
            )
        if notices:
            group = Adw.PreferencesGroup()
            for notice in notices:
                row = Adw.ActionRow(title=notice, title_lines=0, use_markup=False)
                row.add_prefix(Gtk.Image(icon_name="dialog-warning-symbolic"))
                group.add(row)
            panel.add(group)

        levels = Adw.PreferencesGroup(
            title=_("Signature Level"), header_suffix=help_button(HelpTopic.SIGNATURE_LEVELS)
        )
        has_tsa = self._services.timestamper() is not None
        preferred = self._preferred_level()
        self.level_buttons: dict[SignatureLevel, Gtk.CheckButton] = {}
        first: Gtk.CheckButton | None = None
        for level in LEVEL_ORDER:
            _title, description = presentation.LEVELS[level]
            available = has_tsa or level is SignatureLevel.B_B
            button = Gtk.CheckButton(group=first, sensitive=available, valign=Gtk.Align.CENTER)
            first = first or button
            button.connect("toggled", self._on_level, level)
            row = Adw.ActionRow(
                title=presentation.level_title(level),
                subtitle=_(description) if available else _(presentation.NEEDS_TSA),
                activatable_widget=button,
                sensitive=available,
                use_markup=False,
            )
            row.set_subtitle_lines(0)
            row.add_prefix(button)
            levels.add(row)
            self.level_buttons[level] = button
        chosen = preferred if has_tsa or preferred is SignatureLevel.B_B else SignatureLevel.B_B
        self.level_buttons[chosen].set_active(True)
        panel.add(levels)

        data = Adw.PreferencesGroup(title=_("Signature Data"))
        settings = self._services.settings
        self.reason = Adw.EntryRow(title=_("Reason"), use_markup=False)
        self.location = Adw.EntryRow(title=_("Location"), use_markup=False)
        if settings is not None:
            self.reason.set_text(settings.get_string("signature-reason"))
            self.location.set_text(settings.get_string("signature-location"))
        data.add(self.reason)
        data.add(self.location)

        self.preview = PdfPreview(self.data)
        self.preview.on_box_changed = lambda _box: self.update_appearance()
        if self.preview.page_count:
            panel.add(self._visible_group())
        panel.add(data)
        layout = Gtk.Box()
        layout.append(self.preview)
        layout.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        layout.append(panel)
        return layout

    def _visible_group(self) -> Adw.PreferencesGroup:
        """Visible signature (CU-02): on or off, its appearance, and the box on the preview."""
        settings = self._services.settings
        group = Adw.PreferencesGroup(title=_("Visible Signature"))
        self.visible = Adw.SwitchRow(
            title=_("Show the Signature on the Page"),
            subtitle=_("Drag on the page to place it; drag the box to move it."),
            subtitle_lines=0,
        )
        labels = [_(label) for _kind, label in APPEARANCES]
        # The value goes in the subtitle, in full (see berigna.ui.preferences._combo).
        self.appearance = Adw.ComboRow(
            title=_("Appearance"),
            model=Gtk.StringList.new(labels),
            factory=label_factory(visible=False),
            list_factory=label_factory(visible=True),
            subtitle_lines=0,
        )
        kind = settings.get_string("appearance-kind") if settings else "text"
        kinds = [k.value for k, _label in APPEARANCES]
        self.appearance.set_selected(kinds.index(kind) if kind in kinds else 0)
        self.appearance.connect("notify::selected", lambda *_a: self.update_appearance())
        self.visible.connect("notify::active", lambda *_a: self._on_visible())
        self.reason.connect("changed", lambda _e: self.update_appearance())
        self.location.connect("changed", lambda _e: self.update_appearance())
        group.add(self.visible)
        group.add(self.appearance)
        self.visible.set_active(settings.get_boolean("visible-signature") if settings else False)
        self._on_visible()
        return group

    def appearance_kind(self) -> AppearanceKind:
        return APPEARANCES[self.appearance.get_selected()][0]

    def _image(self, kind: AppearanceKind) -> Path | None:
        directory = self._services.appearance_dir
        return stored_image(directory, kind) if directory is not None else None

    def _on_visible(self) -> None:
        active = self.visible.get_active()
        self.appearance.set_sensitive(active)
        self.preview.set_box(self.preview.box or self.preview.default_box() if active else None)
        self.update_appearance()

    def visible_signature(self) -> VisibleSignature | None:
        box = self.preview.box
        if box is None or not self.visible.get_active():
            return None
        settings = self._services.settings
        language = settings.get_string("appearance-language") if settings else "es_PE"
        kind = self.appearance_kind()
        return VisibleSignature(
            box.page,
            (box.x, box.y, box.width, box.height),
            kind,
            self._image(kind),
            Language(language),
        )

    def update_appearance(self) -> None:
        """Draw the appearance in the box with sample data: the real name and DNI come from
        the card when signing."""
        visible = self.visible_signature()
        kind = self.appearance_kind()
        missing = kind in (AppearanceKind.RUBRIC, AppearanceKind.LOGO) and not self._image(kind)
        label = _(APPEARANCES[self.appearance.get_selected()][1])
        warning = _("Load the image in Preferences → Visible Signature.")
        self.appearance.set_subtitle(f"{label}\n{warning}" if missing else label)
        if visible is None:
            self.preview.set_appearance(None)
            return
        sample = StampData(
            _("NAMES AND SURNAMES"),
            "****0000",
            dt.datetime.now().astimezone(),
            self.reason.get_text().strip() or None,
            self.location.get_text().strip() or None,
        )
        try:
            self.preview.set_appearance(render_appearance(visible, sample))
        except AppearanceError:
            self.preview.set_appearance(None)

    def _preferred_level(self) -> SignatureLevel:
        settings = self._services.settings
        if settings is None:
            return SignatureLevel.B_LT
        return SignatureLevel(settings.get_string("default-level"))

    def _on_level(self, button: Gtk.CheckButton, level: SignatureLevel) -> None:
        if button.get_active():
            self._level = level

    def _busy(self) -> Gtk.Widget:
        self._busy_page = Adw.StatusPage(paintable=Adw.SpinnerPaintable())
        self._busy_page.get_paintable().set_widget(self._busy_page)
        return self._busy_page

    def _set_busy(self, title: str) -> bool:
        self._busy_page.set_title(title)
        self._stack.set_visible_child_name("busy")
        self._sign.set_sensitive(False)
        return GLib.SOURCE_REMOVE

    def _back_to_form(self) -> None:
        self._stack.set_visible_child_name("form")
        self._sign.set_sensitive(not self.document.locked)

    def _show(self, name: str, child: Gtk.Widget) -> None:
        old = self._stack.get_child_by_name(name)
        if old is not None:
            self._stack.remove(old)
        self._stack.add_named(child, name)
        self._stack.set_visible_child_name(name)

    # -- Flow ----------------------------------------------------------------------------------

    def start(self, level: SignatureLevel | None = None) -> None:
        """Sign at ``level`` (the chosen one by default) in a worker thread."""
        level = level or self._level
        settings = self._services.settings
        reason, location = self.reason.get_text().strip(), self.location.get_text().strip()
        if settings is not None:
            settings.set_string("signature-reason", reason)
            settings.set_string("signature-location", location)
        suffix = settings.get_string("output-suffix") if settings else "-firmado"
        folder = settings.get_string("output-directory") if settings else ""
        digest = settings.get_string("digest-algorithm") if settings else "sha256"
        options = PadesOptions(
            reason=reason or None,
            location=location or None,
            digest=cast(HashAlgorithmName, digest),
        )
        # A folder that no longer exists (removed, unmounted) falls back to the original's.
        directory = Path(folder) if folder and Path(folder).is_dir() else None
        output = output_path(self.document.path, suffix, directory)
        visible = self.visible_signature() if self.preview.page_count else None
        self._set_busy(_("Checking your certificate…"))
        services = self._services

        def work() -> None:
            try:
                with services.open_token() as token:
                    result = sign_pdf_file(
                        self.document.path,
                        output,
                        expected_sha256=self.document.sha256,
                        token=token,
                        store=services.trust_store(),
                        ask_pin=lambda check: self._ask_pin(check, level),
                        options=options,
                        level=level,
                        timestamper=services.timestamper(),
                        online=services.online,
                        visible=visible,
                    )
            except BerignaError as exc:
                GLib.idle_add(self._failed, exc, level)
            except Exception:  # never leave the page waiting: report it as unexpected (ERR-000)
                log.exception("signing failed")
                GLib.idle_add(self._failed, None, level)
            else:
                if result.level_note:
                    log.info("level %s reached: %s", result.level.value, result.level_note)
                GLib.idle_add(self._done, result, level)

        threading.Thread(target=work, name="berigna-sign", daemon=True).start()

    def _ask_pin(self, check: SignerCheck, level: SignatureLevel) -> Pin | None:
        """Called by the core in the worker thread; waits for the dialog in the main loop."""
        answered = threading.Event()
        answer: list[Pin | None] = [None]

        def reply(pin: Pin | None) -> None:
            answer[0] = pin
            if pin is not None:
                self._set_busy(_("Signing with your DNIe…"))
            answered.set()

        def show() -> bool:
            self.pin_dialog = PinDialog(self.document, check, level, self._remaining_tries, reply)
            self.pin_dialog.present(self._window.window)
            return GLib.SOURCE_REMOVE

        GLib.idle_add(show)
        answered.wait()
        return answer[0]

    def _done(self, result: SignResult, requested: SignatureLevel) -> bool:
        self.result = result
        self._remaining_tries = None
        page = Adw.StatusPage(
            icon_name="object-select-symbolic",
            title=_("Document signed"),
            description=presentation.signed_summary(result, requested),
        )
        self._sign.set_visible(False)
        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        for label, callback in (
            (_("_Open"), self._open_result),
            (_("Show in _Folder"), self._show_in_folder),
            (_("_Verify"), self._verify_result),
        ):
            button = Gtk.Button(label=label, use_underline=True)
            button.add_css_class("pill")
            button.connect("clicked", lambda _b, c=callback: c())
            buttons.append(button)
        page.set_child(buttons)
        self._show("done", page)
        return GLib.SOURCE_REMOVE

    def _failed(self, error: BerignaError | None, level: SignatureLevel) -> bool:
        if isinstance(error, SigningCancelledError):
            self._back_to_form()
            self._window.toast(_("Signature cancelled. The PIN was not sent."))
            return GLib.SOURCE_REMOVE
        if isinstance(error, PinIncorrectError) and error.remaining_tries != 0:
            # CU-01 6a: back to the PIN dialog, which shows the tries left (P-07). Sending the
            # PIN again still needs the user to type it and confirm (P-06).
            self._remaining_tries = error.remaining_tries
            self.start(level)
            return GLib.SOURCE_REMOVE
        if isinstance(error, PinIncorrectError):  # no tries left: the card is now blocked
            error = PinBlockedError("no tries left")
        message = explain_error(error.code if error else "ERR-000", catalogue()) or ""
        page = Adw.StatusPage(
            icon_name="dialog-error-symbolic",
            title=_("The document was not signed"),
            description=message,
        )
        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        back = Gtk.Button(label=_("_Back"), use_underline=True)
        back.add_css_class("pill")
        back.connect("clicked", lambda _b: self._back_to_form())
        buttons.append(back)
        if isinstance(error, LevelNotAvailableError) and level is not SignatureLevel.B_B:
            basic = Gtk.Button(label=_("Sign Without _Timestamp (B-B)"), use_underline=True)
            basic.add_css_class("pill")
            basic.add_css_class("suggested-action")
            basic.connect("clicked", lambda _b: self.start(SignatureLevel.B_B))
            buttons.append(basic)
        page.set_child(buttons)
        self._show("error", page)
        return GLib.SOURCE_REMOVE

    # -- After signing -------------------------------------------------------------------------

    def _open_result(self) -> None:
        if self.result is not None:
            launcher = Gtk.FileLauncher(file=Gio.File.new_for_path(str(self.result.output)))
            launcher.launch(self._window.window, None, None)

    def _show_in_folder(self) -> None:
        if self.result is not None:
            launcher = Gtk.FileLauncher(file=Gio.File.new_for_path(str(self.result.output)))
            launcher.open_containing_folder(self._window.window, None, None)

    def _verify_result(self) -> None:
        if self.result is not None:
            self._window.open_file(Gio.File.new_for_path(str(self.result.output)))
