# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Visible signature in the interface (CU-02; RF-012, RF-081, RF-092)."""

import io
from collections.abc import Generator
from pathlib import Path

from gi.repository import Gtk
from PIL import Image
from pyhanko.pdf_utils.reader import PdfFileReader

from berigna.core.appearance import AppearanceKind, DniDisplay
from berigna.ui.application import BerignaApplication
from berigna.ui.i18n import _
from berigna.ui.preview import EDGE, PdfPreview, SignatureBox
from berigna.ui.signing import SigningPage
from conftest import drive, wait_until
from support.pdfs import two_page_pdf
from support.pki import minimal_pdf


def _page(app: BerignaApplication) -> SigningPage:
    assert app.main_window is not None
    assert app.main_window.signing is not None
    return app.main_window.signing


def _signing(app: BerignaApplication) -> bool:
    return app.main_window is not None and app.main_window.signing is not None


def _png(path: Path) -> Path:
    Image.new("RGBA", (120, 40), (35, 28, 30, 255)).save(path)
    return path


def test_sign_with_a_qr_code(app: BerignaApplication, tmp_path: Path) -> None:
    path = tmp_path / "contrato.pdf"
    path.write_bytes(two_page_pdf())

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        assert page.appearance.get_selected() == 0  # "No visible"
        assert page.appearance.get_subtitle() == "No visible"
        assert page.preview.box is None
        assert page.preview.page == 0  # it opens on the first page
        page.appearance.set_selected(4)  # QR code
        box = page.preview.box
        assert box is not None
        assert box.page == 0  # the page being shown, bottom right (decisión del 2026-10-30)
        assert box.y == EDGE
        assert page.preview.page == 0  # no jump: the user picks the page
        assert page.appearance_kind() is AppearanceKind.QR
        assert page.appearance.get_subtitle() == "Código QR"
        assert page.preview._appearance is not None  # drawn with sample data
        visible = page.visible_signature()
        assert visible is not None
        assert visible.dni is DniDisplay.LAST_FOUR
        page._sign.emit("clicked")
        yield from wait_until(lambda: page.pin_dialog is not None, 10)
        assert page.pin_dialog is not None
        page.pin_dialog.entry.set_text("123456")
        page.pin_dialog.sign_button.emit("clicked")
        yield from wait_until(lambda: page.result is not None, 10)

    drive(app, script, args=[str(path)])
    signed = (tmp_path / "contrato-firmado.pdf").read_bytes()
    [signature] = PdfFileReader(io.BytesIO(signed)).embedded_signatures
    rect = [float(value) for value in signature.sig_field["/Rect"]]
    assert rect[1] == EDGE  # placed where the box was
    assert b"Arvo-Bold" in signed


def test_rubric_without_an_image_is_refused_before_the_pin(
    app: BerignaApplication, tmp_path: Path
) -> None:
    path = tmp_path / "contrato.pdf"
    path.write_bytes(minimal_pdf())

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        page.appearance.set_selected(2)  # rubric, none loaded
        assert page.appearance.get_subtitle().endswith("Preferencias → Firma visible.")
        assert page.preview._appearance is None
        page._sign.emit("clicked")
        yield from wait_until(lambda: page._stack.get_visible_child_name() == "error", 10)
        assert page.pin_dialog is None
        error = page._stack.get_child_by_name("error")
        assert error.get_description().startswith("No se puede dibujar la firma visible")
        page.appearance.set_selected(0)
        assert page.visible_signature() is None
        assert page.preview.box is None

    drive(app, script, args=[str(path)])


def test_images_in_the_preferences(app: BerignaApplication, tmp_path: Path) -> None:
    toasts: list[str] = []
    bad = tmp_path / "mala.png"
    bad.write_text("no es una imagen")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        app.show_preferences()
        dialog = app.preferences
        assert dialog is not None
        dialog.toast = toasts.append  # type: ignore[method-assign]
        row, remove = dialog.image_rows[AppearanceKind.LOGO]
        assert row.get_subtitle() == "Sin imagen"
        assert not remove.get_visible()
        dialog.set_image(AppearanceKind.LOGO, _png(tmp_path / "logo.png"))
        assert row.get_subtitle() == "Cargada"
        assert remove.get_visible()
        dialog.set_image(AppearanceKind.RUBRIC, bad)
        dialog.remove_image(AppearanceKind.LOGO)
        assert row.get_subtitle() == "Sin imagen"
        assert app.settings is not None
        assert dialog.appearance.get_subtitle() == "No visible"
        dialog.appearance.set_selected(3)
        assert app.settings.get_string("appearance-kind") == "logo"
        assert app.settings.get_boolean("visible-signature")
        dialog.appearance.set_selected(0)
        assert not app.settings.get_boolean("visible-signature")
        assert app.settings.get_string("appearance-kind") == "logo"  # kept for next time
        app.settings.reset("appearance-kind")
        dialog.dni.set_selected(1)
        assert app.settings.get_string("appearance-dni") == "full"
        assert dialog.dni.get_subtitle() == "Completo (12345678)"
        app.settings.reset("appearance-dni")

    drive(app, script)
    assert len(toasts) == 1
    assert toasts[0].startswith("No se puede dibujar la firma visible")


class FakeDrag:
    def __init__(self, x: float, y: float) -> None:
        self.start = (x, y)
        self.state: object = None

    def get_start_point(self) -> tuple[bool, float, float]:
        return True, *self.start

    def set_state(self, state: object) -> bool:
        self.state = state
        return True


def test_moving_resizing_and_scrolling() -> None:
    """Drag the box to move it, its corner to resize it, anywhere else to scroll (2026-10-28)."""
    preview = PdfPreview(minimal_pdf())
    width, height = preview.page_size(0)
    preview._transform = (0.0, 0.0, 1.0, height)  # one widget pixel per point
    changes: list[SignatureBox] = []
    preview.set_box(SignatureBox(0, 100, 100, 200, 60))
    preview.on_box_changed = changes.append  # set_box activates the visible signature
    assert preview.cursor(150, height - 130) == "move"
    assert preview.cursor(300, height - 100) == "se-resize"  # bottom right corner
    assert preview.cursor(20, 20) == "grab"
    # Drag from inside the box: it moves, and stays on the page.
    start_x, start_y = 150, height - 130
    preview._on_drag_begin(None, start_x, start_y)
    preview._on_drag_update(FakeDrag(start_x, start_y), 1000, 0)
    assert preview.box == SignatureBox(0, width - 200, 100, 200, 60)
    preview._on_drag_end(None, 0, 0)
    # Drag the corner: the top left corner stays, never below the minimum size.
    preview.set_box(SignatureBox(0, 100, 100, 200, 60))
    corner = (300, height - 100)
    preview._on_drag_begin(None, *corner)
    preview._on_drag_update(FakeDrag(*corner), -50, 40)  # narrower and taller
    assert preview.box == SignatureBox(0, 100, 60, 150, 100)
    preview._on_drag_update(FakeDrag(*corner), -1000, -1000)
    assert preview.box == SignatureBox(0, 100, 160 - 15, 40, 15)
    preview._on_drag_end(None, 0, 0)
    assert len(changes) == 3  # a drag and a new box
    # Drag outside: the page scrolls, the box stays.
    box = preview.box
    preview._on_drag_begin(None, 20, 20)
    drag = FakeDrag(20, 20)
    preview._on_drag_update(drag, -30, -40)
    assert preview.box == box
    assert drag.state == Gtk.EventSequenceState.CLAIMED
    preview._on_drag_end(None, 0, 0)
    assert len(changes) == 3  # scrolling is not a change of the box
    preview._on_drag_update(FakeDrag(0, 0), 1, 1)  # after the end: ignored


def test_the_box_follows_the_page_shown() -> None:
    """The user picks the page of the visible signature freely: the box travels to the page
    shown when it changes, clamped inside each page (decisión del 2026-10-30)."""
    preview = PdfPreview(two_page_pdf())
    width, _height = preview.page_size(0)
    preview.set_box(SignatureBox(0, width - 240, 100, 200, 60))
    preview.show_page(1)  # navigation, without any jump away
    assert preview.page == 1
    other_width, other_height = preview.page_size(1)
    # The box keeps its geometry, clamped to the size of the page shown.
    assert preview.box == SignatureBox(
        1, other_width - 240, 100 if other_height >= 160 else 40, 200, 60
    )
    preview.show_page(-1)  # clamped navigation: back to the first page
    assert preview.box.page == 0
    # A box placed beyond the bounds of a page is brought inside it (any size).
    assert SignatureBox(0, 9999.0, 9999.0, 200, 60).on_page(1, (400.0, 300.0)) == SignatureBox(
        1, 200.0, 240.0, 200, 60
    )


def test_page_number_and_zoom() -> None:
    preview = PdfPreview(two_page_pdf())
    assert (preview.page, preview.zoom) == (0, None)
    assert preview._zoom_label.get_label() == _("Fit")
    assert not preview._zoom_label.get_sensitive()
    preview.page_entry.set_text("2")  # typed page number
    preview.page_entry.emit("activate")
    assert preview.page == 1
    assert not preview._next.get_sensitive()
    preview.show_page(9)  # clamped
    assert preview.page_entry.get_text() == "2"
    preview.go_to("abc")  # not a number: the current page stays
    assert preview.page_entry.get_text() == "2"
    preview._fit_zoom = 0.6
    preview.zoom_in()  # from the fitted size, the next step
    assert preview.zoom == 0.75
    assert preview._zoom_label.get_label() == "75 %"
    width, _height = preview.page_size(1)
    assert preview._area.get_content_width() == round(width * 0.75 * 96 / 72) + 24
    preview.set_zoom(10)
    assert preview.zoom == 4.0
    assert not preview._zoom_in.get_sensitive()
    preview.zoom_out()
    assert preview.zoom == 3.0
    preview.set_zoom(None)
    assert preview._area.get_content_width() == 1
    preview.zoom_out()
    assert preview.zoom == 0.5


def test_the_name_goes_in_bold() -> None:
    from berigna.ui.widgets import brand_markup

    assert brand_markup("kept by berigna & co.") == "kept by <b>berigna</b> &amp; co."
    # Not inside file names.
    assert brand_markup("berigna-prueba.pdf: berigna.") == "berigna-prueba.pdf: <b>berigna</b>."


def test_icon_buttons_are_named() -> None:
    """RNF-USA-03: an icon-only button gets its tooltip as accessible name."""
    from berigna.ui.widgets import named

    button = Gtk.Button(icon_name="zoom-in-symbolic", tooltip_text="Acercar")
    assert named(button) is button
    assert button.get_tooltip_text() == "Acercar"
