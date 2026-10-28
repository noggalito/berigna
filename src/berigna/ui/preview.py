# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""PDF preview with Poppler (ADR-0016), kept in one module so the engine can change.

Poppler only draws: what is signed are the bytes the core read, whose SHA-256 is checked
before the PIN and right before signing (RF-018).
"""

from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Poppler", "0.18")
from gi.repository import Adw, GLib, Gtk, Poppler  # noqa: E402

from berigna.ui.i18n import _  # noqa: E402

_MARGIN = 12


class PdfPreview(Gtk.Box):
    """One page at a time, fitted to the available space, with page navigation."""

    def __init__(self, data: bytes) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, hexpand=True, vexpand=True)
        try:
            self._document: Poppler.Document | None = Poppler.Document.new_from_bytes(
                GLib.Bytes.new(data), None
            )
        except GLib.Error:
            self._document = None
        self.page_count = self._document.get_n_pages() if self._document else 0
        self.page = 0
        if self._document is None or self.page_count == 0:
            self.append(
                Adw.StatusPage(
                    icon_name="x-office-document-symbolic",
                    title=_("No preview"),
                    description=_("This PDF cannot be shown, but it can still be signed."),
                    vexpand=True,
                )
            )
            return

        self._area = Gtk.DrawingArea(hexpand=True, vexpand=True)
        self._area.set_draw_func(self._draw)
        self.append(self._area)

        bar = Gtk.CenterBox(margin_top=6, margin_bottom=6)
        controls = Gtk.Box(spacing=6)
        self._previous = Gtk.Button(
            icon_name="go-previous-symbolic", tooltip_text=_("Previous Page")
        )
        self._next = Gtk.Button(icon_name="go-next-symbolic", tooltip_text=_("Next Page"))
        self._label = Gtk.Label()
        self._previous.connect("clicked", lambda _b: self.show_page(self.page - 1))
        self._next.connect("clicked", lambda _b: self.show_page(self.page + 1))
        for widget in (self._previous, self._label, self._next):
            controls.append(widget)
        bar.set_center_widget(controls)
        self.append(bar)
        self.show_page(0)

    def show_page(self, number: int) -> None:
        """Show page ``number`` (from 0), clamped to the document."""
        self.page = max(0, min(number, self.page_count - 1))
        self._label.set_label(
            _("Page {page} of {total}").format(page=self.page + 1, total=self.page_count)
        )
        self._previous.set_sensitive(self.page > 0)
        self._next.set_sensitive(self.page < self.page_count - 1)
        self._area.queue_draw()

    def _draw(self, _area: Gtk.DrawingArea, cr: Any, width: int, height: int) -> None:
        if self._document is None:
            return
        page = self._document.get_page(self.page)
        page_width, page_height = page.get_size()
        scale = min((width - 2 * _MARGIN) / page_width, (height - 2 * _MARGIN) / page_height)
        if scale <= 0:
            return
        x = (width - page_width * scale) / 2
        y = (height - page_height * scale) / 2
        cr.translate(x, y)
        cr.scale(scale, scale)
        cr.set_source_rgb(1, 1, 1)
        cr.rectangle(0, 0, page_width, page_height)
        cr.fill()
        page.render(cr)
