# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing in the interface with a simulated DNIe (CU-01, CU-03; P-01, P-06, P-07)."""

from collections.abc import Generator
from pathlib import Path

from gi.repository import Adw, Gio, Gtk
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import MDPPerm

from berigna.core.documents import inspect_document
from berigna.core.formats.pades import SignatureLevel
from berigna.core.i18n import Language
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.ui import i18n
from berigna.ui.application import BerignaApplication
from berigna.ui.preview import PdfPreview
from berigna.ui.signing import PinDialog, SigningPage
from conftest import FakeReaders, drive, open_card, wait_until
from sim.dnie_v2 import DnieV2Simulator
from support.certified import certified_pdf
from support.pki import Pki, minimal_pdf
from support.signed import sign
from support.tsa import make_timestamper


def _page(app: BerignaApplication) -> SigningPage:
    assert app.main_window is not None
    assert app.main_window.signing is not None
    return app.main_window.signing


def _signing(app: BerignaApplication) -> bool:
    return app.main_window is not None and app.main_window.signing is not None


def _shown(page: SigningPage) -> str:
    return str(page._stack.get_visible_child_name())


def _dialog(page: SigningPage) -> Generator[None, None, PinDialog]:
    yield from wait_until(lambda: page.pin_dialog is not None, 10)
    assert page.pin_dialog is not None
    return page.pin_dialog


def _enter_pin(page: SigningPage, pin: str) -> Generator[None, None, None]:
    dialog = yield from _dialog(page)
    page.pin_dialog = None
    dialog.entry.set_text(pin)
    assert dialog.sign_button.get_sensitive()
    dialog.sign_button.emit("clicked")
    assert dialog.entry.get_text() == ""  # the entry is cleared once the PIN is taken


def _pdf(tmp_path: Path, data: bytes | None = None, name: str = "contrato.pdf") -> Path:
    path = tmp_path / name
    path.write_bytes(data if data is not None else minimal_pdf())
    return path


def test_sign_a_pdf(app: BerignaApplication, tmp_path: Path) -> None:
    path = _pdf(tmp_path)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        # Without a TSA only the basic level can be chosen (DP-02).
        sensitive = {lv for lv, b in page.level_buttons.items() if b.get_sensitive()}
        assert sensitive == {SignatureLevel.B_B}
        assert page.level_buttons[SignatureLevel.B_B].get_active()
        assert page.preview.page_count == 1
        page.reason.select(2)  # "En señal de conformidad"
        page.location.select(len(page.location.labels) - 1, "Cusco")  # "Otra ubicación…"
        assert page.location.entry.get_visible()
        page._sign.emit("clicked")
        yield from _enter_pin(page, "123456")
        yield from wait_until(lambda: _shown(page) == "done", 10)
        assert page.result is not None
        assert page.result.output == tmp_path / "contrato-firmado.pdf"
        assert not page._sign.get_visible()
        assert app.settings is not None
        assert app.settings.get_string("signature-location") == "Cusco"
        assert app.settings.get_string("signature-reason-kind") == "agreement"
        assert app.settings.get_strv("recent-locations")[0] == "Cusco"
        page._verify_result()  # the signed copy opens in the verification page
        yield from wait_until(
            lambda: app.main_window is not None and app.main_window.verification is not None
        )

    drive(app, script, args=[str(path)])
    info = inspect_document(tmp_path / "contrato-firmado.pdf")
    assert info.signatures == 1
    with (tmp_path / "contrato-firmado.pdf").open("rb") as signed:
        signature = PdfFileReader(signed).embedded_signatures[0].sig_object
        assert (signature["/Reason"], signature["/Location"]) == (
            "En señal de conformidad",
            "Cusco",
        )
    assert path.read_bytes() == minimal_pdf()  # the original is untouched


def test_wrong_pin_shows_the_tries_left_and_then_blocks(
    app: BerignaApplication, card: DnieV2Simulator, tmp_path: Path
) -> None:
    path = _pdf(tmp_path)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        page._sign.emit("clicked")
        yield from _enter_pin(page, "000000")
        dialog = yield from _dialog(page)  # shown again, never retried on its own (P-06)
        texts = _labels(dialog)
        assert any("Te quedan 2 intentos" in text for text in texts)
        page.pin_dialog = None
        dialog.entry.set_text("111111")
        dialog.sign_button.emit("clicked")
        yield from _enter_pin(page, "222222")
        yield from wait_until(lambda: _shown(page) == "error", 10)
        error = page._stack.get_child_by_name("error")
        assert "bloqueado" in error.get_description()

    drive(app, script, args=[str(path)])
    assert card.tries_left == 0
    assert not (tmp_path / "contrato-firmado.pdf").exists()


def test_cancel_sends_no_pin(
    app: BerignaApplication, card: DnieV2Simulator, tmp_path: Path
) -> None:
    path = _pdf(tmp_path)
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        assert app.main_window is not None
        app.main_window.toast = toasts.append  # type: ignore[method-assign]
        page._sign.emit("clicked")
        dialog = yield from _dialog(page)
        dialog.cancel_button.emit("clicked")
        yield from wait_until(lambda: _shown(page) == "form", 10)
        assert page._sign.get_sensitive()

    drive(app, script, args=[str(path)])
    assert toasts == ["Firma cancelada. No se envió el PIN."]
    assert card.tries_left == card.max_tries
    assert not (tmp_path / "contrato-firmado.pdf").exists()


def test_changing_the_language_cancels_an_open_pin_dialog(
    app: BerignaApplication, card: DnieV2Simulator, tmp_path: Path
) -> None:
    """The window is rebuilt in the new language; the worker waiting for the PIN must not be
    left behind holding the card."""
    path = _pdf(tmp_path)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        page._sign.emit("clicked")
        dialog = yield from _dialog(page)
        assert app.settings is not None
        app.settings.set_string("ui-language", "quz_PE")
        assert dialog._answered
        yield from wait_until(lambda: _shown(page) == "form", 10)  # the worker has finished
        app.settings.reset("ui-language")

    drive(app, script, args=[str(path)])
    assert card.tries_left == card.max_tries
    assert not (tmp_path / "contrato-firmado.pdf").exists()


def test_level_without_revocation_data_offers_the_basic_level(
    readers: FakeReaders, pki: Pki, card: DnieV2Simulator, tmp_path: Path
) -> None:
    stamper, _tsa = make_timestamper(pki)
    app = BerignaApplication(
        status_source=lambda: readers,
        trust_store=lambda: pki.store,
        open_token=lambda: open_card(card),
        timestamper=lambda: stamper,
        online=False,
        unique=False,
    )
    path = _pdf(tmp_path)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        assert all(button.get_sensitive() for button in page.level_buttons.values())
        assert page.level_buttons[SignatureLevel.B_LT].get_active()  # default-level
        page._sign.emit("clicked")
        yield from wait_until(lambda: _shown(page) == "error", 10)
        assert page.pin_dialog is None  # known before the PIN (RF-006)
        basic = _button(page._stack.get_child_by_name("error"), "Firmar sin sello de tiempo (B-B)")
        basic.emit("clicked")
        yield from _enter_pin(page, "123456")
        yield from wait_until(lambda: _shown(page) == "done", 10)
        assert page.result is not None
        assert page.result.level is SignatureLevel.B_B

    drive(app, script, args=[str(path)])


def test_certified_document_cannot_be_signed(
    app: BerignaApplication, pki: Pki, tmp_path: Path
) -> None:
    path = _pdf(tmp_path, certified_pdf(pki, MDPPerm.NO_CHANGES))

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(
            lambda: (
                app.main_window is not None
                and app.main_window.verification is not None
                and app.main_window.verification._stack.get_visible_child_name() == "result"
            )
        )
        assert app.main_window is not None
        verification = app.main_window.verification
        assert verification is not None
        assert not verification._sign.get_sensitive()
        app.main_window.sign(verification.document)
        page = _page(app)
        assert not page._sign.get_sensitive()

    drive(app, script, args=[str(path)])


def test_add_a_signature_to_a_signed_pdf(app: BerignaApplication, pki: Pki, tmp_path: Path) -> None:
    signed, _leaf = sign(pki, minimal_pdf(), "PRIMER FIRMANTE")
    path = _pdf(tmp_path, signed)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(
            lambda: (
                app.main_window is not None
                and app.main_window.verification is not None
                and app.main_window.verification._sign.get_sensitive()
            )
        )
        assert app.main_window is not None
        verification = app.main_window.verification
        assert verification is not None
        verification._sign.emit("clicked")
        page = _page(app)
        stack = app.main_window._navigation.get_navigation_stack()
        assert stack.get_n_items() == 3  # start, verification and signing (CU-03)
        # Offline, the first signature is indeterminate: the page warns before signing.
        notices = _labels(page._stack.get_child_by_name("form"))
        assert any("no es válida" in text for text in notices)
        page._sign.emit("clicked")
        yield from _enter_pin(page, "123456")
        yield from wait_until(lambda: _shown(page) == "done", 10)

    drive(app, script, args=[str(path)])
    assert inspect_document(tmp_path / "contrato-firmado.pdf").signatures == 2


def test_pin_dialog_in_quechua_offers_spanish(app: BerignaApplication, tmp_path: Path) -> None:
    path = _pdf(tmp_path)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        assert app.settings is not None
        app.settings.set_string("ui-language", "quz_PE")
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        page._sign.emit("clicked")
        dialog = yield from _dialog(page)
        spanish = _button(dialog, "Kastilla simipi ñawinchay")  # "Leer en español", in Quechua
        spanish.emit("clicked")
        yield
        dialog.cancel_button.emit("clicked")
        yield from wait_until(lambda: _shown(page) == "form", 10)
        assert i18n.current_language() is Language.QUZ_PE

    drive(app, script, args=[str(path)])


def test_preview_pages_and_unreadable_pdf() -> None:
    from support.pdfs import two_page_pdf

    preview = PdfPreview(two_page_pdf())
    assert preview.page_count == 2
    preview.show_page(5)
    assert preview.page == 1
    assert preview.page_entry.get_text() == "2"
    assert preview._label.get_label() == "de 2"
    preview.show_page(-1)
    assert preview.page == 0
    assert not preview._previous.get_sensitive()
    broken = PdfPreview(b"%PDF-1.7 roto")
    assert broken.page_count == 0


def _walk(widget: Gtk.Widget) -> Generator[Gtk.Widget, None, None]:
    child = widget.get_first_child()
    while child is not None:
        yield child
        yield from _walk(child)
        child = child.get_next_sibling()


def _labels(widget: Gtk.Widget) -> list[str]:
    texts = [w.get_label() for w in _walk(widget) if isinstance(w, Gtk.Label)]
    texts += [w.get_title() for w in _walk(widget) if isinstance(w, Adw.PreferencesRow)]
    return [str(text) for text in texts if text]


def _button(widget: Gtk.Widget, label: str) -> Gtk.Button:
    for child in _walk(widget):
        if isinstance(child, Gtk.Button) and str(child.get_label()).replace("_", "") == label:
            return child
    raise AssertionError(f"no button {label!r}")


def test_unexpected_errors_do_not_leave_the_page_waiting(
    readers: FakeReaders, pki: Pki, tmp_path: Path
) -> None:
    def broken_reader() -> DnieV2Token:
        raise RuntimeError("driver bug")

    app = BerignaApplication(
        status_source=lambda: readers,
        trust_store=lambda: pki.store,
        open_token=broken_reader,
        online=False,
        unique=False,
    )
    path = _pdf(tmp_path)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        page._sign.emit("clicked")
        yield from wait_until(lambda: _shown(page) == "error", 10)
        assert page._stack.get_child_by_name("error").get_description() == "Error inesperado."

    drive(app, script, args=[str(path)])


def test_reason_and_location_lists(app: BerignaApplication, tmp_path: Path) -> None:
    """The last reason and location come back; recent locations are offered (2026-10-28)."""
    path = _pdf(tmp_path)
    settings = Gio.Settings.new("com.noggalito.Berigna")
    keys = ("recent-locations", "signature-location", "signature-reason-kind", "signature-reason")
    settings.set_strv("recent-locations", ["Sullana", "Cusco"])
    settings.set_string("signature-location", "Cusco")
    settings.set_string("signature-reason-kind", "other")
    settings.set_string("signature-reason", "Por encargo")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app))
        page = _page(app)
        assert page.location.labels == ["Sin ubicación", "Sullana", "Cusco", "Otra ubicación…"]
        assert page.location_value() == "Cusco"
        assert not page.location.entry.get_visible()
        assert page.reason.other
        assert page.reason.entry.get_visible()
        assert page.reason_value() == "Por encargo"
        page.reason.select(1)
        assert page.reason_value() == "Autoría del documento"
        assert not page.reason.entry.get_visible()
        page.reason.select(0)
        page.location.select(0)
        assert (page.reason_value(), page.location_value()) == (None, None)

    try:
        drive(app, script, args=[str(path)])
    finally:
        for key in keys:
            settings.reset(key)
