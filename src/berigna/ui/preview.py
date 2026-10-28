# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""PDF preview with Poppler (ADR-0016), kept in one module so the engine can change.

Poppler only draws: what is signed are the bytes the core read, whose SHA-256 is checked
before the PIN and right before signing (RF-018).

The preview can also hold the box of a visible signature (CU-02): dragging on the page draws a
new box, dragging from inside the box moves it, and the appearance is drawn inside it.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Poppler", "0.18")
from gi.repository import Adw, GLib, Gtk, Poppler  # noqa: E402

from berigna.ui.i18n import _  # noqa: E402

_MARGIN = 12
DEFAULT_BOX = (200.0, 60.0)  # width, height in points
MIN_BOX = (40.0, 15.0)
EDGE = 36.0  # points from the page edges of the default box


@dataclass(frozen=True)
class SignatureBox:
    """Page (from 0) and box (x, y, width, height) in points, origin at the bottom left."""

    page: int
    x: float
    y: float
    width: float
    height: float

    def contains(self, page: int, x: float, y: float) -> bool:
        return (
            page == self.page
            and self.x <= x <= self.x + self.width
            and self.y <= y <= self.y + self.height
        )


def _load(data: bytes) -> Poppler.Document | None:
    try:
        return Poppler.Document.new_from_bytes(GLib.Bytes.new(data), None)
    except GLib.Error:
        return None


class PdfPreview(Gtk.Box):
    """One page at a time, fitted to the available space, with page navigation."""

    def __init__(self, data: bytes) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, hexpand=True, vexpand=True)
        self._document = _load(data)
        self.page_count = self._document.get_n_pages() if self._document else 0
        self.page = 0
        self.box: SignatureBox | None = None
        self.on_box_changed: Callable[[SignatureBox], None] | None = None
        self._appearance: Poppler.Document | None = None
        self._transform = (0.0, 0.0, 1.0, 0.0)  # x, y offset, scale, page height
        self._drag: tuple[str, float, float, SignatureBox | None] | None = None
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
        drag = Gtk.GestureDrag()
        drag.connect("drag-begin", self._on_drag_begin)
        drag.connect("drag-update", self._on_drag_update)
        drag.connect("drag-end", self._on_drag_end)
        self._area.add_controller(drag)
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

    def page_size(self, number: int) -> tuple[float, float]:
        if self._document is None:
            return 0.0, 0.0
        width, height = self._document.get_page(number).get_size()
        return float(width), float(height)

    def show_page(self, number: int) -> None:
        """Show page ``number`` (from 0), clamped to the document."""
        self.page = max(0, min(number, self.page_count - 1))
        self._label.set_label(
            _("Page {page} of {total}").format(page=self.page + 1, total=self.page_count)
        )
        self._previous.set_sensitive(self.page > 0)
        self._next.set_sensitive(self.page < self.page_count - 1)
        self._area.queue_draw()

    # -- Visible signature box -------------------------------------------------------------

    def default_box(self) -> SignatureBox:
        """Bottom right of the last page, where signatures usually go."""
        last = self.page_count - 1
        page_width, _height = self.page_size(last)
        width, height = DEFAULT_BOX
        return SignatureBox(last, max(0.0, page_width - width - EDGE), EDGE, width, height)

    def set_box(self, box: SignatureBox | None) -> None:
        """Show ``box`` (None hides it) and turn to its page."""
        self.box = box
        if box is not None and self.page_count:
            self.show_page(box.page)
        elif self.page_count:
            self._area.queue_draw()

    def set_appearance(self, pdf: bytes | None) -> None:
        """The rendered appearance to draw inside the box."""
        self._appearance = _load(pdf) if pdf else None
        if self.page_count:
            self._area.queue_draw()

    def to_page(self, x: float, y: float) -> tuple[float, float]:
        """Widget coordinates to page points (origin at the bottom left)."""
        left, top, scale, page_height = self._transform
        return (x - left) / scale, page_height - (y - top) / scale

    def _on_drag_begin(self, _gesture: Gtk.GestureDrag, x: float, y: float) -> None:
        if self.box is None:
            return
        px, py = self.to_page(x, y)
        mode = "move" if self.box.contains(self.page, px, py) else "draw"
        self._drag = (mode, px, py, self.box)

    def _on_drag_update(self, gesture: Gtk.GestureDrag, dx: float, dy: float) -> None:
        if self._drag is None:
            return
        mode, px, py, start = self._drag
        _ok, x0, y0 = gesture.get_start_point()
        qx, qy = self.to_page(x0 + dx, y0 + dy)
        page_width, page_height = self.page_size(self.page)
        if mode == "move" and start is not None:
            x = min(max(0.0, start.x + qx - px), page_width - start.width)
            y = min(max(0.0, start.y + qy - py), page_height - start.height)
            self.box = SignatureBox(self.page, x, y, start.width, start.height)
        else:
            x1, x2 = sorted((min(max(px, 0.0), page_width), min(max(qx, 0.0), page_width)))
            y1, y2 = sorted((min(max(py, 0.0), page_height), min(max(qy, 0.0), page_height)))
            width, height = max(x2 - x1, MIN_BOX[0]), max(y2 - y1, MIN_BOX[1])
            self.box = SignatureBox(
                self.page, min(x1, page_width - width), min(y1, page_height - height), width, height
            )
        self._area.queue_draw()

    def _on_drag_end(self, _gesture: Gtk.GestureDrag, _dx: float, _dy: float) -> None:
        if self._drag is not None and self.box is not None and self.on_box_changed:
            self.on_box_changed(self.box)
        self._drag = None

    # -- Drawing ---------------------------------------------------------------------------

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
        self._transform = (x, y, scale, page_height)
        cr.translate(x, y)
        cr.scale(scale, scale)
        cr.set_source_rgb(1, 1, 1)
        cr.rectangle(0, 0, page_width, page_height)
        cr.fill()
        page.render(cr)
        if self.box is not None and self.box.page == self.page:
            self._draw_box(cr, self.box, page_height, scale)

    def _draw_box(self, cr: Any, box: SignatureBox, page_height: float, scale: float) -> None:
        top = page_height - box.y - box.height
        if self._appearance is not None:
            appearance = self._appearance.get_page(0)
            stamp_width, stamp_height = appearance.get_size()
            cr.save()
            cr.translate(box.x, top)
            cr.scale(box.width / stamp_width, box.height / stamp_height)
            appearance.render(cr)
            cr.restore()
        cr.set_source_rgba(0.21, 0.52, 0.89, 0.9)
        cr.set_line_width(1.5 / scale)
        cr.set_dash([4 / scale, 3 / scale])
        cr.rectangle(box.x, top, box.width, box.height)
        cr.stroke()
