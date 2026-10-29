# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
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
    DniDisplay,
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
    SignerCertificateError,
    SigningCancelledError,
    TokenError,
)
from berigna.core.formats.pades import PadesOptions, SignatureLevel  # noqa: E402
from berigna.core.i18n import Language, translations  # noqa: E402
from berigna.core.reasons import TEXTS as REASON_TEXTS  # noqa: E402
from berigna.core.reasons import Reason, reason_text  # noqa: E402
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
from berigna.ui.widgets import brand_markup, label_factory  # noqa: E402

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


# Kinds of visible signature, in the order of the list, after "Not visible" (decisions of
# 2026-10-28: one list, as other signing programs have, instead of a switch and a list).
APPEARANCES: tuple[tuple[AppearanceKind | None, str], ...] = (
    (None, N_("Not visible")),
    (AppearanceKind.TEXT, N_("Text only")),
    (AppearanceKind.RUBRIC, N_("Handwritten signature (image)")),
    (AppearanceKind.LOGO, N_("Logo")),
    (AppearanceKind.QR, N_("QR code")),
)
# How the visible signature shows the DNI (decision of 2026-10-28).
DNI_OPTIONS = (
    (DniDisplay.LAST_FOUR, N_("Last four digits (****5678)")),
    (DniDisplay.FULL, N_("Full (12345678)")),
    (DniDisplay.HIDDEN, N_("Do not show")),
)
DNI_SAMPLES = {
    DniDisplay.LAST_FOUR: "****0000",
    DniDisplay.FULL: "00000000",
    DniDisplay.HIDDEN: None,
}
# Reasons in the list, after "No reason" and before "Other…".
REASONS = (
    Reason.AUTHORSHIP,
    Reason.AGREEMENT,
    Reason.ENDORSEMENT,
    Reason.APPROVAL,
    Reason.ON_BEHALF,
)
RECENT_LOCATIONS = 5


class ChoiceWithOther:
    """A list of choices whose last item, "Other…", shows an entry for free text (decision of
    2026-10-28). The first item is "none"."""

    def __init__(self, title: str, other: tuple[str, str], labels: list[str]) -> None:
        other_label, other_title = other  # in the list, and the title of the entry
        self.labels = [*labels, other_label]
        self.combo = Adw.ComboRow(
            title=title,
            model=Gtk.StringList.new(self.labels),
            factory=label_factory(visible=False),
            list_factory=label_factory(visible=True),
            subtitle_lines=0,
        )
        self.entry = Adw.EntryRow(title=other_title, use_markup=False)
        self.combo.connect("notify::selected", lambda *_a: self._sync())
        self._sync()

    @property
    def other(self) -> bool:
        return self.combo.get_selected() == len(self.labels) - 1

    def select(self, index: int, text: str = "") -> None:
        self.entry.set_text(text)
        self.combo.set_selected(index)
        self._sync()

    def _sync(self) -> None:
        self.combo.set_subtitle(self.labels[self.combo.get_selected()])
        self.entry.set_visible(self.other)

    def connect(self, callback: Callable[[], None]) -> None:
        self.combo.connect("notify::selected", lambda *_a: callback())
        self.entry.connect("changed", lambda _e: callback())

    def add_to(self, group: Adw.PreferencesGroup) -> None:
        group.add(self.combo)
        group.add(self.entry)


def preferred_level(settings: Gio.Settings | None) -> SignatureLevel:
    if settings is None:
        return SignatureLevel.B_LT
    return SignatureLevel(settings.get_string("default-level"))


def output_settings(settings: Gio.Settings | None) -> tuple[str, Path | None]:
    """Suffix and folder of signed files; a folder that no longer exists (removed, unmounted)
    falls back to the original's."""
    suffix = settings.get_string("output-suffix") if settings else "-firmado"
    folder = settings.get_string("output-directory") if settings else ""
    return suffix, Path(folder) if folder and Path(folder).is_dir() else None


class LevelChoice:
    """The signature levels, recommended first; those that need a TSA are disabled without
    one (DP-02). Shared by the signing page and the batch page."""

    def __init__(self, services: "SigningServices") -> None:
        self.group = Adw.PreferencesGroup(
            title=_("Signature Level"), header_suffix=help_button(HelpTopic.SIGNATURE_LEVELS)
        )
        has_tsa = services.timestamper() is not None
        preferred = preferred_level(services.settings)
        self.level = SignatureLevel.B_B
        self.buttons: dict[SignatureLevel, Gtk.CheckButton] = {}
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
            self.group.add(row)
            self.buttons[level] = button
        chosen = preferred if has_tsa or preferred is SignatureLevel.B_B else SignatureLevel.B_B
        self.buttons[chosen].set_active(True)

    def _on_level(self, button: Gtk.CheckButton, level: SignatureLevel) -> None:
        if button.get_active():
            self.level = level


class SignatureData:
    """Reason and location, in lists with "Other" (2026-10-28), remembered between uses."""

    def __init__(self, settings: Gio.Settings | None) -> None:
        self._settings = settings
        self.group = Adw.PreferencesGroup(
            title=_("Signature Data"),
            description=_(
                "Signature validators such as Firma Perú show them. The reasons of the list are "
                "written in the language of the signature."
            ),
        )
        self.reason = ChoiceWithOther(
            _("Reason"),
            (_("Other reason…"), _("Other Reason")),
            [_("No reason"), *(_(REASON_TEXTS[reason]) for reason in REASONS)],
        )
        self.recent_locations = list(settings.get_strv("recent-locations")) if settings else []
        self.location = ChoiceWithOther(
            _("Location"),
            (_("Other location…"), _("Other Location")),
            [_("No location"), *self.recent_locations],
        )
        if settings is not None:
            self._restore(settings)
        self.reason.add_to(self.group)
        self.location.add_to(self.group)

    def _restore(self, settings: Gio.Settings) -> None:
        """The last reason and location used."""
        kinds = [Reason.NONE, *REASONS, Reason.OTHER]
        kind = Reason(settings.get_string("signature-reason-kind"))
        self.reason.select(kinds.index(kind), settings.get_string("signature-reason"))
        last = settings.get_string("signature-location")
        if last in self.recent_locations:
            self.location.select(self.recent_locations.index(last) + 1)
        elif last:
            self.location.select(len(self.location.labels) - 1, last)

    def language(self) -> Language:
        """The language of the signature (RF-092), also for the reasons of the list."""
        settings = self._settings
        return Language(settings.get_string("appearance-language") if settings else "es_PE")

    def reason_kind(self) -> Reason:
        kinds = [Reason.NONE, *REASONS, Reason.OTHER]
        return kinds[self.reason.combo.get_selected()]

    def reason_value(self) -> str | None:
        """The reason as written in the signature: in the language of the signature (RF-092)."""
        return reason_text(self.reason_kind(), self.reason.entry.get_text(), self.language())

    def location_value(self) -> str | None:
        if self.location.other:
            return self.location.entry.get_text().strip() or None
        index = self.location.combo.get_selected()
        return self.recent_locations[index - 1] if index > 0 else None

    def remember(self) -> None:
        settings, location = self._settings, self.location_value()
        if settings is None:
            return
        settings.set_string("signature-reason-kind", self.reason_kind().value)
        settings.set_string("signature-reason", self.reason.entry.get_text().strip())
        settings.set_string("signature-location", location or "")
        if location:
            recent = [location, *(old for old in self.recent_locations if old != location)]
            settings.set_strv("recent-locations", recent[:RECENT_LOCATIONS])

    def options(self) -> PadesOptions:
        digest = self._settings.get_string("digest-algorithm") if self._settings else "sha256"
        return PadesOptions(
            reason=self.reason_value(),
            location=self.location_value(),
            digest=cast(HashAlgorithmName, digest),
        )


def failure_page(
    window: "MainWindow",
    error: BerignaError | None,
    level: SignatureLevel,
    *,
    title: str,
    back: Callable[[], None],
    retry: Callable[[SignatureLevel], None],
) -> Adw.StatusPage | None:
    """What a failed signing shows, for one document or a batch; None when the flow goes on
    by itself (cancelled before the PIN, or a wrong PIN with tries left)."""
    if isinstance(error, SigningCancelledError):
        back()
        window.toast(_("Signature cancelled. The PIN was not sent."))
        return None
    if isinstance(error, PinIncorrectError) and error.remaining_tries != 0:
        # CU-01 6a: back to the PIN dialog, which shows the tries left (P-07). Sending the PIN
        # again still needs the user to type it and confirm (P-06).
        retry(level)
        return None
    if isinstance(error, PinIncorrectError):  # no tries left: the card is now blocked
        error = PinBlockedError("no tries left")
    message = explain_error(error.code if error else "ERR-000", catalogue()) or ""
    page = Adw.StatusPage(
        icon_name="dialog-error-symbolic", title=title, description=brand_markup(message)
    )
    buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
    back_button = Gtk.Button(label=_("_Back"), use_underline=True)
    back_button.add_css_class("pill")
    back_button.connect("clicked", lambda _b: back())
    buttons.append(back_button)
    if isinstance(error, (TokenError, SignerCertificateError)):
        diagnosis = Gtk.Button(label=_("_Diagnosis"), use_underline=True)
        diagnosis.add_css_class("pill")
        diagnosis.connect("clicked", lambda _b: window.show_diagnostics())
        buttons.append(diagnosis)
    if isinstance(error, LevelNotAvailableError) and level is not SignatureLevel.B_B:
        basic = Gtk.Button(label=_("Sign Without _Timestamp (B-B)"), use_underline=True)
        basic.add_css_class("pill")
        basic.add_css_class("suggested-action")
        basic.connect("clicked", lambda _b: retry(SignatureLevel.B_B))
        buttons.append(basic)
    page.set_child(buttons)
    return page


def ask_pin_in_main_loop(
    window: "MainWindow",
    make_dialog: Callable[[Callable[[Pin | None], None]], "PinDialog"],
    on_pin: Callable[[], object],
) -> Pin | None:
    """Called by the core in a worker thread: shows the PIN dialog in the main loop and waits
    for the user. ``on_pin`` runs when a PIN is given."""
    answered = threading.Event()
    answer: list[Pin | None] = [None]

    def reply(pin: Pin | None) -> None:
        answer[0] = pin
        if pin is not None:
            on_pin()
        answered.set()

    def show() -> bool:
        make_dialog(reply).present(window.window)
        return GLib.SOURCE_REMOVE

    GLib.idle_add(show)
    answered.wait()
    return answer[0]


class PinDialog(Adw.Dialog):
    """Summary of what is going to be signed and the PIN entry (P-01, P-05, P-07)."""

    def __init__(
        self,
        document: DocumentInfo | int,
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
                row = Adw.ActionRow(title=brand_markup(notice), title_lines=0)
                row.add_prefix(Gtk.Image(icon_name="dialog-warning-symbolic"))
                group.add(row)
            panel.add(group)

        self.levels = LevelChoice(self._services)
        self.level_buttons = self.levels.buttons
        panel.add(self.levels.group)
        self.signature_data = SignatureData(self._services.settings)
        self.reason = self.signature_data.reason
        self.location = self.signature_data.location
        data = self.signature_data.group

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
        """Visible signature (CU-02): not visible or its appearance, and the box on the preview."""
        settings = self._services.settings
        group = Adw.PreferencesGroup(
            title=_("Visible Signature"),
            description=_(
                "Drag the box to move it and its corner to resize it; drag the page to scroll "
                "it. In a box taller than wide, the image goes above the text."
            ),
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
        if settings is not None and settings.get_boolean("visible-signature"):
            kind = settings.get_string("appearance-kind")
            kinds = [k.value if k else None for k, _label in APPEARANCES]
            self.appearance.set_selected(kinds.index(kind) if kind in kinds else 1)
        self.appearance.connect("notify::selected", lambda *_a: self._on_visible())
        self.reason.connect(self.update_appearance)
        self.location.connect(self.update_appearance)
        group.add(self.appearance)
        self._on_visible()
        return group

    def reason_value(self) -> str | None:
        return self.signature_data.reason_value()

    def location_value(self) -> str | None:
        return self.signature_data.location_value()

    def _language(self) -> Language:
        return self.signature_data.language()

    def _dni(self) -> DniDisplay:
        settings = self._services.settings
        return DniDisplay(settings.get_string("appearance-dni") if settings else "last-four")

    def appearance_kind(self) -> AppearanceKind | None:
        """The chosen appearance; None: not visible."""
        return APPEARANCES[self.appearance.get_selected()][0]

    def _image(self, kind: AppearanceKind) -> Path | None:
        directory = self._services.appearance_dir
        return stored_image(directory, kind) if directory is not None else None

    def _on_visible(self) -> None:
        active = self.appearance_kind() is not None
        self.preview.set_box(self.preview.box or self.preview.default_box() if active else None)
        self.update_appearance()

    def visible_signature(self) -> VisibleSignature | None:
        box = self.preview.box
        kind = self.appearance_kind()
        if box is None or kind is None:
            return None
        return VisibleSignature(
            box.page,
            (box.x, box.y, box.width, box.height),
            kind,
            self._image(kind),
            self._language(),
            self._dni(),
        )

    def update_appearance(self) -> None:
        """Draw the appearance in the box with sample data: the real name and DNI come from
        the card when signing."""
        visible = self.visible_signature()
        kind = self.appearance_kind()
        missing = (
            kind in (AppearanceKind.RUBRIC, AppearanceKind.LOGO)
            and kind is not None
            and not self._image(kind)
        )
        label = _(APPEARANCES[self.appearance.get_selected()][1])
        warning = _("Load the image in Preferences → Visible Signature.")
        self.appearance.set_subtitle(f"{label}\n{warning}" if missing else label)
        if visible is None:
            self.preview.set_appearance(None)
            return
        sample = StampData(
            _("NAMES AND SURNAMES"),
            DNI_SAMPLES[visible.dni],
            dt.datetime.now().astimezone(),
            self.reason_value(),
            self.location_value(),
        )
        try:
            self.preview.set_appearance(render_appearance(visible, sample))
        except AppearanceError:
            self.preview.set_appearance(None)

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
        level = level or self.levels.level
        self.signature_data.remember()
        options = self.signature_data.options()
        suffix, directory = output_settings(self._services.settings)
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
        def dialog(reply: Callable[[Pin | None], None]) -> PinDialog:
            self.pin_dialog = PinDialog(self.document, check, level, self._remaining_tries, reply)
            return self.pin_dialog

        return ask_pin_in_main_loop(
            self._window, dialog, lambda: self._set_busy(_("Signing with your DNIe…"))
        )

    def _done(self, result: SignResult, requested: SignatureLevel) -> bool:
        self.result = result
        self._remaining_tries = None
        page = Adw.StatusPage(
            icon_name="object-select-symbolic",
            title=_("Document signed"),
            description=brand_markup(presentation.signed_summary(result, requested)),
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
        if isinstance(error, PinIncorrectError) and error.remaining_tries != 0:
            self._remaining_tries = error.remaining_tries
        page = failure_page(
            self._window,
            error,
            level,
            title=_("The document was not signed"),
            back=self._back_to_form,
            retry=self.start,
        )
        if page is not None:
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
