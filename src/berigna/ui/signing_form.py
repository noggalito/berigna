# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The parts of the signing form that the signing page and the batch page share (BRG-UX-001
§3.2 and §3.4): signature level, reason and location, packaging of CAdES and XAdES, the
settings they read, and the view of a file that is not a PDF (CU-05)."""

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, cast

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, Gtk  # noqa: E402

from berigna.core.appearance import AppearanceKind, DniDisplay  # noqa: E402
from berigna.core.documents import TEXT_PREVIEW_LIMIT, DocumentInfo, text_preview  # noqa: E402
from berigna.core.formats.cades import CadesPackaging  # noqa: E402
from berigna.core.formats.pades import PadesOptions, SignatureLevel  # noqa: E402
from berigna.core.formats.xades import XadesPackaging  # noqa: E402
from berigna.core.i18n import Language  # noqa: E402
from berigna.core.reasons import TEXTS as REASON_TEXTS  # noqa: E402
from berigna.core.reasons import Reason, reason_text  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.token.base import HashAlgorithmName  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.help import HelpTopic, help_button  # noqa: E402
from berigna.ui.i18n import N_, _, catalogue  # noqa: E402
from berigna.ui.widgets import label_factory  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.signing import SigningServices

# Order of the level list: recommended first (BRG-UX-001 §3.2).
LEVEL_ORDER = (SignatureLevel.B_LT, SignatureLevel.B_LTA, SignatureLevel.B_T, SignatureLevel.B_B)


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


def digest_setting(settings: Gio.Settings | None) -> HashAlgorithmName:
    """The hash algorithm of the preferences (RF-080)."""
    return cast(
        HashAlgorithmName, settings.get_string("digest-algorithm") if settings else "sha256"
    )


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
        return PadesOptions(
            reason=self.reason_value(),
            location=self.location_value(),
            digest=digest_setting(self._settings),
        )


class PackagingChoice:
    """The packagings of CAdES and XAdES a file can be signed in, the proposed one first
    (CU-05 step 2). In an XML document that is already signed, the enveloped form is off: it
    would break the signature there (ERR-312)."""

    def __init__(self, document: DocumentInfo) -> None:
        self.group = Adw.PreferencesGroup(title=_("Signature Format"))
        self.buttons: dict[CadesPackaging | XadesPackaging, Gtk.CheckButton] = {}
        packagings = presentation.packagings_for(document.kind)
        blocked = {XadesPackaging.ENVELOPED} if document.signed else set()
        self.packaging = next(p for p in packagings if p not in blocked)
        first: Gtk.CheckButton | None = None
        for packaging in packagings:
            available = packaging not in blocked
            button = Gtk.CheckButton(group=first, sensitive=available, valign=Gtk.Align.CENTER)
            first = first or button
            button.connect("toggled", self._on_toggled, packaging)
            subtitle = (
                presentation.packaging_description(packaging)
                if available
                else explain_error("ERR-312", catalogue()) or ""
            )
            row = Adw.ActionRow(
                title=presentation.packaging_title(packaging),
                subtitle=subtitle,
                activatable_widget=button,
                sensitive=available,
                use_markup=False,
            )
            row.set_subtitle_lines(0)
            row.add_prefix(button)
            self.group.add(row)
            self.buttons[packaging] = button
        self.buttons[self.packaging].set_active(True)

    def _on_toggled(
        self, button: Gtk.CheckButton, packaging: CadesPackaging | XadesPackaging
    ) -> None:
        if button.get_active():
            self.packaging = packaging


def file_view(document: DocumentInfo, data: bytes) -> Gtk.Widget:
    """What the user checks before signing a file that is not a PDF (WYSIWYS, CU-05 step 3):
    name, size, type and SHA-256, and the text when it is a text file."""
    content_type, _uncertain = Gio.content_type_guess(document.path.name, data[:4096])
    details = Adw.PreferencesGroup(
        title=_("File to Sign"), description=presentation.document_summary(document)
    )
    for detail in presentation.file_details(
        document, Gio.content_type_get_description(content_type)
    ):
        row = Adw.ActionRow(
            title=detail.label, subtitle=detail.value, subtitle_selectable=True, use_markup=False
        )
        row.add_css_class("property")
        details.add(row)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, hexpand=True)
    for side in ("top", "bottom", "start", "end"):
        getattr(box, f"set_margin_{side}")(12)
    box.append(details)
    preview = text_preview(data)
    if preview is None:
        notice = Gtk.Label(
            label=_(
                "This file cannot be shown. Check its name, size and SHA-256 before signing: "
                "they identify the file that will be signed."
            ),
            wrap=True,
            xalign=0,
        )
        notice.add_css_class("dimmed")
        box.append(notice)
        return box
    if preview.truncated:
        limit = presentation.file_size(TEXT_PREVIEW_LIMIT)
        notice = Gtk.Label(
            label=_("Only the beginning of the file is shown ({size}).").format(size=limit),
            wrap=True,
            xalign=0,
        )
        notice.add_css_class("dimmed")
        box.append(notice)
    buffer = Gtk.TextBuffer(text=preview.text)
    text = Gtk.TextView(
        buffer=buffer, editable=False, cursor_visible=False, monospace=True, top_margin=6
    )
    for side in ("left", "right", "bottom"):
        getattr(text, f"set_{side}_margin")(6)
    text.update_property([Gtk.AccessibleProperty.LABEL], [_("Content of the file")])
    scrolled = Gtk.ScrolledWindow(child=text, vexpand=True, min_content_height=200)
    frame = Gtk.Frame(child=scrolled)
    box.append(frame)
    return box
