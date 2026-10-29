# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Small widget helpers shared by the pages."""

from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from berigna.core.i18n import NAME, Language, translations  # noqa: E402
from berigna.ui.i18n import N_, _  # noqa: E402

CLOSE = N_("_Close")


def label_factory(*, visible: bool) -> Gtk.SignalListItemFactory:
    """Items of a combo row: wrapped in the list (``visible``), or none next to the title."""
    factory = Gtk.SignalListItemFactory()

    def setup(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        item.set_child(Gtk.Label(xalign=0, wrap=True, max_width_chars=40, visible=visible))

    def bind(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        item.get_child().set_label(item.get_item().get_string())

    factory.connect("setup", setup)
    factory.connect("bind", bind)
    return factory


def brand_markup(text: str) -> str:
    """``text`` as Pango markup, with the program's name in bold (decision of 2026-10-28).
    Every message shown with markup goes through here, which also escapes file names."""
    return NAME.sub("<b>berigna</b>", GLib.markup_escape_text(text))


def named(button: Gtk.Button) -> Gtk.Button:
    """An icon-only button with its tooltip as accessible name, so that Orca reads what it does
    (RNF-USA-03): GTK uses a tooltip only as the description."""
    button.update_property([Gtk.AccessibleProperty.LABEL], [button.get_tooltip_text() or ""])
    return button


def spanish_button(show: Callable[[], None], **properties: object) -> Gtk.Button:
    """ "Read in Spanish" (BRG-UX-001 §4.2): the same text in es_PE without changing the
    language. The banner's "Show in Spanish" is another thing: it changes the language."""
    button = Gtk.Button(label=_("Read in Spanish"), **properties)
    button.add_css_class("flat")
    button.connect("clicked", lambda _button: show())
    return button


def show_in_spanish(parent: Gtk.Widget, heading: str, body: str) -> Adw.AlertDialog:
    """A dialog with a text already in Spanish, closed with a Spanish button."""
    dialog = Adw.AlertDialog(heading=heading, body=body)
    dialog.add_response("close", translations(Language.ES_PE).gettext(CLOSE))
    dialog.present(parent)
    return dialog
