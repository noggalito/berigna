#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Capturas para la metainfo de AppStream (inventario visual §10): 1280x800, datos
ficticios y estilo claro. Genera ``build/capturas/berigna-firma.png`` (vista de firma de
un PDF) y ``build/capturas/berigna-verificacion.png`` (resultado de una verificación). Las
PNG se suben a https://berigna.noggalito.com/screenshots/, las URL que referencia la
metainfo.

Se ejecuta con ``scripts/capturas-metainfo.sh``, que prepara el árbol de Meson, los
catálogos y el display X. La firma y la verificación se hacen sin red y con la tarjeta
simulada y la PKI de pruebas (como los tests de la interfaz), para que ningún dato real
aparezca en las capturas.
"""
from __future__ import annotations

import io
import os
import struct
import subprocess
import sys
import tempfile
import warnings
import zlib
from collections.abc import Callable, Generator
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("GdkX11", "4.0")

from gi.repository import GdkX11, Gio, GLib, Gtk  # noqa: E402

BUILD = REPO / "build" / "meson" / "data"
OUT = REPO / "build" / "capturas"
os.environ.setdefault("BERIGNA_RESOURCES", str(BUILD / "berigna.gresource"))
os.environ["GSETTINGS_SCHEMA_DIR"] = str(BUILD)
os.environ["GSETTINGS_BACKEND"] = "memory"
os.environ["GDK_BACKEND"] = "x11"
os.environ["BERIGNA_LOCALEDIR"] = str(REPO / "build" / "locale")

from berigna.core.i18n import Language  # noqa: E402
from berigna.core.token.dnie_v2 import DnieV2Token, DNIE_V2_ATR  # noqa: E402
from berigna.core.token.monitor import ReaderState  # noqa: E402
from sim.dnie_v2 import DnieV2Simulator  # noqa: E402
from support.cards import make_card  # noqa: E402
from support.pki import build_pki  # noqa: E402
from support.signed import signed_with_revinfo  # noqa: E402

Gio.Resource.load(os.environ["BERIGNA_RESOURCES"])._register()

from berigna.ui import i18n  # noqa: E402
from berigna.ui.application import BerignaApplication  # noqa: E402

WIDTH, HEIGHT = 1280, 800


class FakeReaders:
    """Stands in for PC/SC: one reader with the DNIe inserted, like a real session."""

    def __init__(self) -> None:
        self.current: tuple[ReaderState, ...] = (
            ReaderState(name="Lector de tarjetas", atr=DNIE_V2_ATR),
        )

    def readers(self) -> tuple[ReaderState, ...]:
        return self.current

    def close(self) -> None:
        pass


def wait_until(condition, seconds: float = 10) -> Generator[None, None, None]:
    for _ in range(int(seconds / 0.02)):
        if condition():
            return
        yield
    raise AssertionError("timed out")


def idle(seconds: float) -> Generator[None, None, None]:
    """A few frames, so that the page paints before the capture."""
    yield from wait_until(lambda: True, seconds)


def drive(app: BerignaApplication, script, *, args: list[str] | None = None) -> None:
    """``app`` with its real main loop; ``script`` yields while it waits for something."""
    steps = script(app)
    failure: list[BaseException] = []

    def tick() -> int:
        try:
            next(steps)
            return GLib.SOURCE_CONTINUE
        except StopIteration:
            pass
        except BaseException as exc:  # reported after the loop ends
            failure.append(exc)
        app.quit()
        return GLib.SOURCE_REMOVE

    def start(*_args: object) -> None:
        GLib.timeout_add(20, tick)

    app.connect("startup", start)
    app.run(["berigna", *(args or [])])
    if failure:
        raise failure[0]


def xwd_to_png(raw: Path, png: Path) -> None:
    """An XWD dump of a TrueColor ZPixmap (what ``xwd`` writes for Xvfb) to PNG, scaled to
    exactly ``WIDTH``x``HEIGHT``. Pillow and the header of the XWD format (XWDFile.h):
    ``header_size`` already includes the window name in this xwd variant, the colormap
    entries (XColor, 12 bytes each) come before the pixels when ``ncolors`` > 0, and the
    scanlines go zlib-compressed when the depth is below the bits per pixel."""
    from PIL import Image  # noqa: PLC0415 - the captures only, not the CI

    data = raw.read_bytes()
    header = struct.unpack(">25I", data[:100])
    (
        header_size, file_version, pixmap_format, depth, width, height,
        _xoffset, byte_order, _unit, _bit_order, _pad, bpp, bytes_per_line,
        _class, _red, _green, _blue, _bits_per_rgb, _colormap_entries, ncolors,
        *_rest,
    ) = header
    if file_version != 7 or pixmap_format != 2 or byte_order != 0 or bpp not in (24, 32):
        raise AssertionError(f"formato XWD inesperado: {header[:13]}")
    offset = header_size
    if ncolors:  # the colormap dump: pixel (u32) + rgb (u16) + flags + pad, per entry
        offset += ncolors * 12
    pixels = bytearray()
    if depth < bpp:  # each scanline zlib-compressed, prefixed by its length
        for _row in range(height):
            (line_len,) = struct.unpack(">I", data[offset:offset + 4])
            offset += 4
            pixels += zlib.decompress(data[offset:offset + line_len])
            offset += line_len
    else:
        pixels += data[offset:offset + bytes_per_line * height]
    # Pixels as raw XImage data (little-endian 0xAARRGGBB on disk: [B, G, R, A]), or packed
    # RGB when the depth is 24.
    step = bpp // 8 if depth >= bpp else depth // 8
    rgb = bytearray()
    for pixel in range(width * height):
        start = pixel * step
        if step == 4:
            rgb += bytes((pixels[start + 2], pixels[start + 1], pixels[start]))
        else:
            rgb += pixels[start:start + 3]
    image = Image.frombytes("RGB", (width, height), bytes(rgb))
    image.resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS).save(png)


def example_document() -> bytes:
    """A fictitious one-page PDF with a few paragraphs (no personal data, inventario
    visual §10); reportlab is a berigna dependency."""
    from reportlab.lib.pagesizes import A4  # noqa: PLC0415 - the captures only
    from reportlab.pdfgen import canvas  # noqa: PLC0415

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle("Documento de ejemplo")
    lines = [
        ("Acta de reunión (ejemplo)", 18),
        ("Fecha: 4 de noviembre de 2026", 12),
        ("Asistentes: María Quispe, Jorge Mamani", 12),
        ("", 12),
        ("Se acuerda revisar los documentos antes de firmarlos.", 12),
        ("La firma digital equivale a la firma manuscrita y garantiza", 12),
        ("que el documento no fue modificado después de firmarlo.", 12),
        ("", 12),
        ("Este es un documento de ejemplo con datos ficticios.", 12),
    ]
    y = 780
    for text, size in lines:
        if text:
            pdf.setFont("Helvetica", size)
            pdf.drawString(72, y, text)
        y -= size + 10
    pdf.save()
    return buffer.getvalue()


def snap(window: Gtk.Window, path: Path) -> None:
    """The mapped window as an exactly ``WIDTH``x``HEIGHT`` PNG: ``xwd`` grabs the window
    from the X server (no compositor under Xvfb, so the window shows exactly what berigna
    draws). Needs the Debian package ``x11-apps`` (xwd) and Pillow (a berigna dependency),
    only for generating the captures: the CI does not run this script."""
    surface = window.get_surface()
    if not isinstance(surface, GdkX11.X11Surface):  # pragma: no cover - GDK_BACKEND=x11
        raise AssertionError("la captura necesita el backend X11 (GDK_BACKEND=x11)")
    raw = path.with_suffix(".xwd")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # get_xid, still the X11 way
        xid = surface.get_xid()
    subprocess.run(  # noqa: S603 - fixed command, no untrusted input
        ["xwd", "-silent", "-id", str(xid), "-out", str(raw)], check=True
    )
    try:
        xwd_to_png(raw, path)
    finally:
        raw.unlink()


def _signing_state(app: BerignaApplication) -> str:
    if app.main_window is None or app.main_window.signing is None:
        return ""
    return str(app.main_window.signing._stack.get_visible_child_name())


def _verification_state(app: BerignaApplication) -> str:
    if app.main_window is None or app.main_window.verification is None:
        return ""
    return str(app.main_window.verification._stack.get_visible_child_name())


def main() -> None:
    i18n.set_language(Language.ES_PE)
    pki = build_pki()
    card, _leaf = make_card(pki, "QUISPE MAMANI ROSA FIR 87654321 hard")

    def open_token() -> DnieV2Token:
        card.closed = False
        card.authenticated = False
        return DnieV2Token(card)

    tmp = Path(tempfile.mkdtemp(prefix="berigna-capturas-"))
    to_sign = tmp / "documento-ejemplo.pdf"
    to_sign.write_bytes(example_document())
    signed = tmp / "firmado.pdf"
    signed.write_bytes(signed_with_revinfo(pki))
    OUT.mkdir(parents=True, exist_ok=True)

    # One run of the app per capture, opening the document at startup (the flow the
    # interface tests use): the second navigation of a session leaves the new page
    # without allocation under this Xvfb, so both captures share the same fresh flow.
    def capture_one(
        path: Path,
        ready: Callable[[BerignaApplication], bool],
        allocated: Callable[[BerignaApplication], bool],
        name: str,
    ) -> None:
        app = BerignaApplication(
            status_source=lambda: FakeReaders(),
            trust_store=lambda: pki.store,
            open_token=open_token,
            online=False,
            unique=False,
            appearance_dir=tmp / "apariencia",
            history_path=tmp / "historial.sqlite3",
        )

        def script(application: BerignaApplication) -> Generator[None, None, None]:
            assert application.main_window is not None
            window = application.main_window.window
            # The window is already mapped at its blueprint size: the minimum size forces
            # the 16:9 allocation of the captures (throwaway window, only for these PNGs).
            window.set_size_request(WIDTH, HEIGHT)
            yield from wait_until(lambda: window.get_width() >= WIDTH - 40, 5)
            yield from wait_until(lambda: ready(application), 15)
            # A worker result arrives through GLib.idle_add: wait until its content is
            # allocated (one more frame) before capturing.
            yield from wait_until(lambda: allocated(application), 10)
            yield from idle(1.0)
            snap(window, OUT / name)

        drive(app, script, args=[str(path)])

    # A PDF without signatures opens the signing page (preview rendered: "form").
    capture_one(
        to_sign,
        lambda app: _signing_state(app) == "form",
        lambda app: app.main_window.signing is not None
        and app.main_window.signing.preview.get_width() > 100,
        "berigna-firma.png",
    )
    # The signed PDF opens the verification page, whose result is TOTAL-PASSED offline
    # (embedded revocation data, test PKI).
    capture_one(
        signed,
        lambda app: _verification_state(app) == "result",
        lambda app: app.main_window.verification is not None
        and app.main_window.verification.summary_row.get_width() > 0,
        "berigna-verificacion.png",
    )
    print(f"capturas en {OUT}")


if __name__ == "__main__":
    main()
