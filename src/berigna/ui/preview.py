# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""PDF preview with Poppler (ADR-0016), kept in one module so the engine can change.

Poppler only draws: what is signed are the bytes the core read, whose SHA-256 is checked
before the PIN and right before signing (RF-018).

The preview can also hold the box of a visible signature (CU-02): dragging the box moves it,
dragging its bottom right corner resizes it, and the appearance is drawn inside it.

It opens on the first page, fitted to the window. The page number can be typed, and the page
zoomed in and out (buttons or Ctrl + wheel) to place the box precisely; dragging anywhere
else on the page scrolls it, as in a document viewer (decision of 2026-10-28).

The page and the appearance are rendered once per size and kept as images: a QR code has
hundreds of small squares, and redrawing them on every movement made dragging slow.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import cairo
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Poppler", "0.18")
from gi.repository import Adw, Gdk, GLib, Gtk, Poppler  # noqa: E402

from berigna.ui.i18n import _  # noqa: E402
from berigna.ui.widgets import named  # noqa: E402

_MARGIN = 12
HANDLE = 10.0  # widget pixels around the bottom right corner of the box that resize it
ZOOMS = (0.5, 0.75, 1.0, 1.25, 1.5, 2.0, 3.0, 4.0)  # 1.0: the page at its printed size
_PIXELS_PER_POINT = 96 / 72
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
        self.zoom: float | None = None  # None: the whole page fits
        self._fit_zoom = 1.0  # the zoom that fitting gave on the last draw
        self._drag: tuple[str, float, float, SignatureBox | None] | None = None
        self._page_image: tuple[tuple[int, float, int], cairo.ImageSurface] | None = None
        self._stamp_image: tuple[tuple[float, float, float, int], cairo.ImageSurface] | None = None
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
        wheel = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.VERTICAL)
        wheel.connect("scroll", self._on_scroll)
        self._area.add_controller(wheel)
        motion = Gtk.EventControllerMotion()
        motion.connect(
            "motion", lambda _c, x, y: self._area.set_cursor_from_name(self.cursor(x, y))
        )
        self._area.add_controller(motion)
        self._scrolled = Gtk.ScrolledWindow(child=self._area, hexpand=True, vexpand=True)
        self.append(self._scrolled)

        bar = Gtk.CenterBox(margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)
        zoom = Gtk.Box(spacing=6)
        self._zoom_out = named(
            Gtk.Button(icon_name="zoom-out-symbolic", tooltip_text=_("Zoom Out"))
        )
        self._zoom_label = Gtk.Button(tooltip_text=_("Fit the Page"))
        self._zoom_label.add_css_class("flat")
        self._zoom_in = named(Gtk.Button(icon_name="zoom-in-symbolic", tooltip_text=_("Zoom In")))
        self._zoom_out.connect("clicked", lambda _b: self.zoom_out())
        self._zoom_label.connect("clicked", lambda _b: self.set_zoom(None))
        self._zoom_in.connect("clicked", lambda _b: self.zoom_in())
        for widget in (self._zoom_out, self._zoom_label, self._zoom_in):
            zoom.append(widget)
        bar.set_start_widget(zoom)

        controls = Gtk.Box(spacing=6)
        self._previous = named(
            Gtk.Button(icon_name="go-previous-symbolic", tooltip_text=_("Previous Page"))
        )
        self._next = named(Gtk.Button(icon_name="go-next-symbolic", tooltip_text=_("Next Page")))
        # A plain entry: a spin button adds its own minus and plus buttons next to the arrows.
        self.page_entry = Gtk.Entry(
            input_purpose=Gtk.InputPurpose.DIGITS,
            width_chars=len(str(self.page_count)) + 1,
            max_width_chars=len(str(self.page_count)) + 1,
            xalign=0.5,
            tooltip_text=_("Page Number"),
        )
        self.page_entry.update_property([Gtk.AccessibleProperty.LABEL], [_("Page Number")])
        self._label = Gtk.Label(
            label=_("of {total}").format(total=self.page_count), css_classes=["dimmed"]
        )
        self._previous.connect("clicked", lambda _b: self.show_page(self.page - 1))
        self._next.connect("clicked", lambda _b: self.show_page(self.page + 1))
        self.page_entry.connect("activate", lambda _e: self.go_to(self.page_entry.get_text()))
        for widget in (self._previous, self.page_entry, self._label, self._next):
            controls.append(widget)
        bar.set_center_widget(controls)
        self.append(bar)
        self.show_page(0)
        self.set_zoom(None)

    def page_size(self, number: int) -> tuple[float, float]:
        if self._document is None:
            return 0.0, 0.0
        width, height = self._document.get_page(number).get_size()
        return float(width), float(height)

    def show_page(self, number: int) -> None:
        """Show page ``number`` (from 0), clamped to the document, from its top."""
        page = max(0, min(number, self.page_count - 1))
        changed = page != self.page
        self.page = page
        self.page_entry.set_text(str(page + 1))
        self._previous.set_sensitive(page > 0)
        self._next.set_sensitive(page < self.page_count - 1)
        if changed:
            self._scrolled.get_vadjustment().set_value(0)
        self._resize()

    def go_to(self, typed: str) -> None:
        """The page typed by the user; anything else shows the current one again."""
        number = typed.strip()
        self.show_page(int(number) - 1 if number.isdigit() else self.page)

    # -- Zoom ------------------------------------------------------------------------------

    def set_zoom(self, zoom: float | None) -> None:
        """``zoom`` times the printed size (clamped to :data:`ZOOMS`), or None to fit."""
        self.zoom = None if zoom is None else max(ZOOMS[0], min(zoom, ZOOMS[-1]))
        fitted = self.zoom is None
        self._zoom_label.set_label(_("Fit") if self.zoom is None else f"{round(self.zoom * 100)} %")
        self._zoom_label.set_sensitive(not fitted)
        self._zoom_out.set_sensitive(fitted or self.zoom != ZOOMS[0])
        self._zoom_in.set_sensitive(fitted or self.zoom != ZOOMS[-1])
        self._resize()

    def zoom_in(self) -> None:
        current = self.zoom if self.zoom is not None else self._fit_zoom
        self.set_zoom(next((z for z in ZOOMS if z > current + 1e-6), ZOOMS[-1]))

    def zoom_out(self) -> None:
        current = self.zoom if self.zoom is not None else self._fit_zoom
        self.set_zoom(next((z for z in reversed(ZOOMS) if z < current - 1e-6), ZOOMS[0]))

    def _on_scroll(self, controller: Gtk.EventControllerScroll, _dx: float, dy: float) -> bool:
        """Ctrl + wheel zooms; the wheel alone scrolls."""
        if not controller.get_current_event_state() & Gdk.ModifierType.CONTROL_MASK:
            return False
        if dy < 0:
            self.zoom_in()
        elif dy > 0:
            self.zoom_out()
        return True

    def _resize(self) -> None:
        """Fitting, the area takes the space it is given; zoomed, the size of the page, and
        the scrolled window scrolls it."""
        if self.zoom is None:
            self._area.set_content_width(1)
            self._area.set_content_height(1)
        else:
            width, height = self.page_size(self.page)
            scale = self.zoom * _PIXELS_PER_POINT
            self._area.set_content_width(round(width * scale) + 2 * _MARGIN)
            self._area.set_content_height(round(height * scale) + 2 * _MARGIN)
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
            if self.zoom is not None:
                GLib.idle_add(self._scroll_to_box)
        elif self.page_count:
            self._area.queue_draw()

    def _scroll_to_box(self) -> bool:
        """Zoomed in, centre the box in the view."""
        if self.box is not None:
            left, top, scale, page_height = self._transform
            x = left + self.box.x * scale
            y = top + (page_height - self.box.y - self.box.height) * scale
            for adjustment, value, size in (
                (self._scrolled.get_hadjustment(), x, self.box.width * scale),
                (self._scrolled.get_vadjustment(), y, self.box.height * scale),
            ):
                adjustment.set_value(value - (adjustment.get_page_size() - size) / 2)
        return GLib.SOURCE_REMOVE

    def set_appearance(self, pdf: bytes | None) -> None:
        """The rendered appearance to draw inside the box."""
        self._appearance = _load(pdf) if pdf else None
        self._stamp_image = None
        if self.page_count:
            self._area.queue_draw()

    def to_page(self, x: float, y: float) -> tuple[float, float]:
        """Widget coordinates to page points (origin at the bottom left)."""
        left, top, scale, page_height = self._transform
        return (x - left) / scale, page_height - (y - top) / scale

    def _hit(self, x: float, y: float) -> str:
        """What a drag starting at widget (x, y) does: resize, move or scroll."""
        if self.box is not None and self.box.page == self.page:
            left, top, scale, page_height = self._transform
            corner_x = left + (self.box.x + self.box.width) * scale
            corner_y = top + (page_height - self.box.y) * scale
            if abs(x - corner_x) <= HANDLE and abs(y - corner_y) <= HANDLE:
                return "resize"
            px, py = self.to_page(x, y)
            if self.box.contains(self.page, px, py):
                return "move"
        return "scroll"

    def cursor(self, x: float, y: float) -> str:
        return {"resize": "se-resize", "move": "move", "scroll": "grab"}[self._hit(x, y)]

    def _on_drag_begin(self, _gesture: Gtk.GestureDrag, x: float, y: float) -> None:
        px, py = self.to_page(x, y)
        mode = self._hit(x, y)
        self._drag = (mode, px, py, self.box)
        if mode == "scroll":
            self._area.set_cursor_from_name("grabbing")

    def _on_drag_update(self, gesture: Gtk.GestureDrag, dx: float, dy: float) -> None:
        if self._drag is None:
            return
        mode, px, py, start = self._drag
        if mode == "scroll" or start is None:
            # The offsets are in the area's coordinates, which move as it scrolls: the new
            # position is the current one minus the offset since the start.
            for adjustment, offset in (
                (self._scrolled.get_hadjustment(), dx),
                (self._scrolled.get_vadjustment(), dy),
            ):
                adjustment.set_value(adjustment.get_value() - offset)
            gesture.set_state(Gtk.EventSequenceState.CLAIMED)
            return
        _ok, x0, y0 = gesture.get_start_point()
        qx, qy = self.to_page(x0 + dx, y0 + dy)
        page_width, page_height = self.page_size(self.page)
        if mode == "move":
            x = min(max(0.0, start.x + qx - px), page_width - start.width)
            y = min(max(0.0, start.y + qy - py), page_height - start.height)
            self.box = SignatureBox(self.page, x, y, start.width, start.height)
        else:  # resize from the bottom right corner; the top left corner stays
            top = start.y + start.height
            width = min(max(MIN_BOX[0], start.width + qx - px), page_width - start.x)
            height = min(max(MIN_BOX[1], start.height - (qy - py)), top)
            self.box = SignatureBox(self.page, start.x, top - height, width, height)
        self._area.queue_draw()

    def _on_drag_end(self, _gesture: Gtk.GestureDrag, _dx: float, _dy: float) -> None:
        moved = self._drag is not None and self._drag[0] != "scroll"
        if moved and self.box is not None and self.on_box_changed:
            self.on_box_changed(self.box)
        self._drag = None
        self._area.set_cursor_from_name(None)

    # -- Drawing ---------------------------------------------------------------------------

    def _draw(self, _area: Gtk.DrawingArea, cr: Any, width: int, height: int) -> None:
        if self._document is None:
            return
        page_width, page_height = self.page_size(self.page)
        if self.zoom is None:
            scale = min((width - 2 * _MARGIN) / page_width, (height - 2 * _MARGIN) / page_height)
            if scale <= 0:
                return
            self._fit_zoom = scale / _PIXELS_PER_POINT
        else:
            scale = self.zoom * _PIXELS_PER_POINT
        x = max(_MARGIN, (width - page_width * scale) / 2)
        y = max(_MARGIN, (height - page_height * scale) / 2)
        self._transform = (x, y, scale, page_height)
        cr.translate(x, y)
        cr.set_source_surface(self._page_surface(self._document.get_page(self.page), scale), 0, 0)
        cr.paint()
        cr.scale(scale, scale)
        if self.box is not None and self.box.page == self.page:
            self._draw_box(cr, self.box, page_height, scale)

    def _render(self, width: float, height: float, scale: float, draw: Any) -> cairo.ImageSurface:
        """An image of ``width`` x ``height`` points at ``scale`` widget pixels per point, at
        the screen's resolution."""
        factor = self._area.get_scale_factor()
        surface = cairo.ImageSurface(
            cairo.FORMAT_ARGB32,
            max(1, round(width * scale * factor)),
            max(1, round(height * scale * factor)),
        )
        surface.set_device_scale(factor, factor)
        context = cairo.Context(surface)
        context.scale(scale, scale)
        draw(context)
        surface.flush()
        return surface

    def _page_surface(self, page: Poppler.Page, scale: float) -> cairo.ImageSurface:
        key = (self.page, round(scale, 4), self._area.get_scale_factor())
        if self._page_image is None or self._page_image[0] != key:
            width, height = page.get_size()

            def draw(context: cairo.Context) -> None:  # type: ignore[type-arg]
                context.set_source_rgb(1, 1, 1)
                context.paint()
                page.render(context)

            self._page_image = (key, self._render(width, height, scale, draw))
        return self._page_image[1]

    def _stamp_surface(self, box: SignatureBox, scale: float) -> cairo.ImageSurface | None:
        if self._appearance is None:
            return None
        factor = self._area.get_scale_factor()
        key = (round(box.width, 2), round(box.height, 2), round(scale, 4), factor)
        if self._stamp_image is None or self._stamp_image[0] != key:
            appearance = self._appearance.get_page(0)
            stamp_width, stamp_height = appearance.get_size()

            def draw(context: cairo.Context) -> None:  # type: ignore[type-arg]
                context.scale(box.width / stamp_width, box.height / stamp_height)
                appearance.render(context)

            self._stamp_image = (key, self._render(box.width, box.height, scale, draw))
        return self._stamp_image[1]

    def _draw_box(self, cr: Any, box: SignatureBox, page_height: float, scale: float) -> None:
        top = page_height - box.y - box.height
        stamp = self._stamp_surface(box, scale)
        if stamp is not None:
            cr.save()
            cr.translate(box.x, top)
            cr.scale(1 / scale, 1 / scale)
            cr.set_source_surface(stamp, 0, 0)
            cr.paint()
            cr.restore()
        cr.set_source_rgba(0.21, 0.52, 0.89, 0.9)
        cr.set_line_width(1.5 / scale)
        cr.set_dash([4 / scale, 3 / scale])
        cr.rectangle(box.x, top, box.width, box.height)
        cr.stroke()
        # The resize handle, at the bottom right corner.
        side = HANDLE / scale
        cr.set_dash([])
        cr.rectangle(box.x + box.width - side / 2, top + box.height - side / 2, side, side)
        cr.fill()
