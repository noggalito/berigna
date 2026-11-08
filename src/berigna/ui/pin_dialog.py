# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The PIN dialog (P-01, P-05, P-07; BRG-UX-001 §3.3), for one document or a batch.

The core asks for the PIN from a worker thread, after validating the certificate and probing
the TSA (RF-006): :func:`ask_pin_in_main_loop` shows :class:`PinDialog` in the main loop and
waits for the user. The PIN is sent once per explicit confirmation (P-06)."""

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from berigna.core.documents import DocumentInfo  # noqa: E402
from berigna.core.formats.pades import SignatureLevel  # noqa: E402
from berigna.core.i18n import Language, translations  # noqa: E402
from berigna.core.signing import Packaging  # noqa: E402
from berigna.core.token.pin import Pin  # noqa: E402
from berigna.core.validation import SignerCheck  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.i18n import _, current_language  # noqa: E402
from berigna.ui.widgets import show_in_spanish, spanish_button  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow


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
        packaging: Packaging = None,
    ) -> None:
        super().__init__(title=_("Confirm Signature"), content_width=420)
        self._reply = reply
        self._answered = False
        self._summary = (document, check, level, packaging)

        summary = Adw.PreferencesGroup()
        for detail in presentation.pin_summary(document, check, level, packaging=packaging):
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
            box.append(spanish_button(self._show_spanish, halign=Gtk.Align.START))

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

    def cancel(self) -> None:
        """Answer "no PIN" and close, when the window under the dialog is going away."""
        if not self._answered:
            self._answer(None)
            self.force_close()

    def _answer(self, pin: Pin | None) -> None:
        if not self._answered:
            self._answered = True
            self._reply(pin)

    def _show_spanish(self) -> None:
        """The summary in Spanish, without changing the language (BRG-UX-001 §4.2)."""
        spanish = translations(Language.ES_PE)
        document, check, level, packaging = self._summary
        rows = presentation.pin_summary(document, check, level, spanish, packaging)
        body = "\n".join(f"{row.label}: {row.value}" for row in rows)
        show_in_spanish(self, spanish.gettext("Confirm Signature"), body)
