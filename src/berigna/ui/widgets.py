# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Small widget helpers shared by the pages."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402

from berigna.core.i18n import NAME  # noqa: E402


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
