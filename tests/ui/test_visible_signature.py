# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Visible signature in the interface (CU-02; RF-012, RF-081, RF-092)."""

import io
from collections.abc import Generator
from pathlib import Path

from PIL import Image
from pyhanko.pdf_utils.reader import PdfFileReader

from berigna.core.appearance import AppearanceKind
from berigna.ui.application import BerignaApplication
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
        assert not page.visible.get_active()
        assert page.preview.box is None
        page.visible.set_active(True)
        box = page.preview.box
        assert box is not None
        assert box.page == 1  # the last page, bottom right
        assert box.y == EDGE
        assert page.preview.page == 1
        page.appearance.set_selected(3)  # QR code
        assert page.appearance_kind() is AppearanceKind.QR
        assert page.appearance.get_subtitle() == "Código QR"
        assert page.preview._appearance is not None  # drawn with sample data
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
        page.visible.set_active(True)
        page.appearance.set_selected(1)  # rubric, none loaded
        assert page.appearance.get_subtitle().endswith("Preferencias → Firma visible.")
        assert page.preview._appearance is None
        page._sign.emit("clicked")
        yield from wait_until(lambda: page._stack.get_visible_child_name() == "error", 10)
        assert page.pin_dialog is None
        error = page._stack.get_child_by_name("error")
        assert error.get_description().startswith("No se puede dibujar la firma visible")
        page.visible.set_active(False)
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
        dialog.appearance.set_selected(2)
        assert app.settings is not None
        assert app.settings.get_string("appearance-kind") == "logo"
        app.settings.reset("appearance-kind")

    drive(app, script)
    assert len(toasts) == 1
    assert toasts[0].startswith("No se puede dibujar la firma visible")


class FakeDrag:
    def __init__(self, x: float, y: float) -> None:
        self.start = (x, y)

    def get_start_point(self) -> tuple[bool, float, float]:
        return True, *self.start


def test_drawing_and_moving_the_box() -> None:
    preview = PdfPreview(minimal_pdf())
    width, height = preview.page_size(0)
    preview._transform = (0.0, 0.0, 1.0, height)  # one widget pixel per point
    changes: list[SignatureBox] = []
    preview.on_box_changed = changes.append
    preview._on_drag_begin(None, 10, 10)  # no box: nothing happens
    assert preview._drag is None
    preview.set_box(SignatureBox(0, 100, 100, 200, 60))
    # Drag from inside the box: it moves, and stays on the page.
    start_x, start_y = 150, height - 130
    preview._on_drag_begin(None, start_x, start_y)
    preview._on_drag_update(FakeDrag(start_x, start_y), 1000, 0)
    assert preview.box == SignatureBox(0, width - 200, 100, 200, 60)
    preview._on_drag_end(None, 0, 0)
    # Drag outside: a new box, never smaller than the minimum.
    preview._on_drag_begin(None, 20, height - 20)
    preview._on_drag_update(FakeDrag(20, height - 20), 5, -3)
    assert preview.box is not None
    assert (preview.box.width, preview.box.height) == (40, 15)
    preview._on_drag_end(None, 0, 0)
    assert len(changes) == 2
    preview._on_drag_update(FakeDrag(0, 0), 1, 1)  # after the end: ignored


def test_the_name_goes_in_bold() -> None:
    from berigna.ui.widgets import brand_markup

    assert brand_markup("kept by berigna & co.") == "kept by <b>berigna</b> &amp; co."
