# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Files that are not PDF in the interface: signing them in CAdES or XAdES (CU-05) and
verifying ``.p7s``, ``.p7m``, ``.xml`` and ``.xsig`` (CU-06, RF-051, RF-052)."""

import hashlib
import json
from collections.abc import Generator, Iterator
from pathlib import Path

from gi.repository import Adw, Gtk

from berigna.core.documents import DocumentKind
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.xades import XadesPackaging
from berigna.core.signing import sign_cades_file, sign_xades_file
from berigna.core.token.pin import Pin
from berigna.core.validation import CadesVerification, XadesVerification
from berigna.ui.application import BerignaApplication
from berigna.ui.signing import SigningPage
from berigna.ui.verification import VerificationPage, content_name
from conftest import drive, open_card, wait_until
from sim.dnie_v2 import DnieV2Simulator
from support.pki import Pki

CSV = b"nombre;monto\nRosa Quispe;100\n"
XML = b'<?xml version="1.0" encoding="UTF-8"?>\n<factura><total>100</total></factura>\n'


def _walk(widget: Gtk.Widget) -> Iterator[Gtk.Widget]:
    yield widget
    child = widget.get_first_child()
    while child is not None:
        yield from _walk(child)
        child = child.get_next_sibling()


def _rows(widget: Gtk.Widget) -> dict[str, str]:
    return {
        str(row.get_title()): str(row.get_subtitle())
        for row in _walk(widget)
        if isinstance(row, Adw.ActionRow)
    }


def _signing(app: BerignaApplication) -> SigningPage | None:
    return app.main_window.signing if app.main_window is not None else None


def _verification(app: BerignaApplication) -> VerificationPage | None:
    return app.main_window.verification if app.main_window is not None else None


def _shown(page: SigningPage | VerificationPage) -> str:
    return str(page._stack.get_visible_child_name())


def _sign_with_pin(page: SigningPage) -> Generator[None, None, dict[str, str]]:
    """Click Sign, read the PIN dialog's summary and send the PIN."""
    page._sign.emit("clicked")
    yield from wait_until(lambda: page.pin_dialog is not None, 10)
    dialog = page.pin_dialog
    assert dialog is not None
    summary = _rows(dialog)
    dialog.entry.set_text("123456")
    dialog.sign_button.emit("clicked")
    yield from wait_until(lambda: _shown(page) == "done", 20)
    return summary


def _signed(
    card: DnieV2Simulator,
    pki: Pki,
    source: Path,
    output: Path,
    packaging: CadesPackaging | XadesPackaging,
) -> Path:
    """A signature made by the core with the simulated card, as another program would."""
    sign = sign_cades_file if isinstance(packaging, CadesPackaging) else sign_xades_file
    with open_card(card) as token:
        sign(
            source,
            output,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            token=token,
            store=pki.store,
            ask_pin=lambda _check: Pin("123456"),
            packaging=packaging,  # type: ignore[arg-type]
            online=False,
        )
    return output


def test_any_file_is_signed_in_cades_and_verified(app: BerignaApplication, tmp_path: Path) -> None:
    """CU-05: name, size, type, SHA-256 and the text; CAdES detached proposed; the .p7s
    found next to its original when it is verified (RF-051)."""
    path = tmp_path / "planilla.csv"
    path.write_bytes(CSV)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app) is not None)
        page = _signing(app)
        assert page is not None
        assert page.preview is None
        assert page.formats is not None
        assert page.packaging() is CadesPackaging.DETACHED
        assert list(page.formats.buttons) == [CadesPackaging.DETACHED, CadesPackaging.ENVELOPING]
        rows = _rows(page.formats.group)
        assert "Firma Perú no reconoce la extensión .p7m" in rows["CAdES, envolvente (.p7m)"]
        assert "Firma Perú" not in rows["CAdES, separada (.p7s)"]
        details = _rows(page.page)
        assert details["Nombre"] == "planilla.csv"
        assert details["Tamaño"] == f"{len(CSV)} bytes"
        sha = hashlib.sha256(CSV).hexdigest().upper()
        assert details["SHA-256"].replace(" ", "") == sha
        views = [w for w in _walk(page.page) if isinstance(w, Gtk.TextView)]
        buffer = views[0].get_buffer()
        text = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
        assert text == CSV.decode()
        assert not any(
            w.get_label() == "Motivo" for w in _walk(page.page) if isinstance(w, Gtk.Label)
        )

        summary = yield from _sign_with_pin(page)
        assert summary["Formato"] == "CAdES, separada (.p7s)"
        assert summary["Documento"] == f"planilla.csv ({len(CSV)} bytes)"
        assert page.result is not None
        assert page.result.output == tmp_path / "planilla.csv.p7s"

        page._verify_result()
        yield from wait_until(lambda: _verification(app) is not None)
        verification = _verification(app)
        assert verification is not None
        yield from wait_until(lambda: _shown(verification) == "result", 20)
        assert isinstance(verification.verification, CadesVerification)
        assert verification.original == path
        assert not verification._sign.get_visible()  # no countersignature in 1.0 (RF-023)
        assert _rows(verification.page)["Archivo firmado"] == "planilla.csv"
        report = json.loads(verification.report("json"))
        assert report["signatures"][0]["format"] == "CAdES"
        assert report["signatures"][0]["packaging"] == "p7s"
        assert report["signed_file"] == {
            "name": "planilla.csv",
            "sha256": hashlib.sha256(CSV).hexdigest(),
        }
        assert verification.report("pdf-es").startswith(b"%PDF")

    drive(app, script, args=[str(path)])
    assert path.read_bytes() == CSV  # the original is untouched


def test_a_binary_file_is_not_shown_as_text(app: BerignaApplication, tmp_path: Path) -> None:
    path = tmp_path / "foto.bin"
    path.write_bytes(bytes(range(256)) * 4)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app) is not None)
        page = _signing(app)
        assert page is not None
        assert not any(isinstance(w, Gtk.TextView) for w in _walk(page.page))
        labels = [str(w.get_label()) for w in _walk(page.page) if isinstance(w, Gtk.Label)]
        assert any(label.startswith("Este archivo no se puede mostrar.") for label in labels)
        assert _rows(page.page)["Tamaño"] == "1,0 kB (1 024 bytes)"

    drive(app, script, args=[str(path)])


def test_an_xml_document_is_signed_in_xades(app: BerignaApplication, tmp_path: Path) -> None:
    """CU-05 step 2: XAdES enveloped proposed for XML; the user can choose another form.
    The detached .xsig is verified with the document next to it."""
    path = tmp_path / "factura.xml"
    path.write_bytes(XML)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _signing(app) is not None)
        page = _signing(app)
        assert page is not None
        assert page.formats is not None
        assert page.packaging() is XadesPackaging.ENVELOPED
        page.formats.buttons[XadesPackaging.DETACHED].set_active(True)
        summary = yield from _sign_with_pin(page)
        assert summary["Formato"] == "XAdES, separada (.xsig)"
        assert page.result is not None
        assert page.result.output == tmp_path / "factura.xml.xsig"

        page._verify_result()
        yield from wait_until(lambda: _verification(app) is not None)
        verification = _verification(app)
        assert verification is not None
        yield from wait_until(lambda: _shown(verification) == "result", 20)
        assert isinstance(verification.verification, XadesVerification)
        assert verification.original == path
        assert not verification._sign.get_visible()  # it would sign the .xsig itself
        report = json.loads(verification.report("json"))
        assert report["signatures"][0]["scope"] == "external"

    drive(app, script, args=[str(path)])
    assert path.read_bytes() == XML


def test_a_detached_signature_without_its_file_asks_for_it(
    app: BerignaApplication, card: DnieV2Simulator, pki: Pki, tmp_path: Path
) -> None:
    source = tmp_path / "planilla.csv"
    source.write_bytes(CSV)
    signature = _signed(card, pki, source, tmp_path / "copia.p7s", CadesPackaging.DETACHED)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _verification(app) is not None)
        page = _verification(app)
        assert page is not None
        yield from wait_until(lambda: _shown(page) == "original")
        page.verify_with(source)
        yield from wait_until(lambda: _shown(page) == "result", 20)
        assert isinstance(page.verification, CadesVerification)
        assert page.verification.signatures[0].subindication != "HASH_FAILURE"

    drive(app, script, args=[str(signature)])


def test_the_content_of_a_p7m_can_be_saved(
    app: BerignaApplication, card: DnieV2Simulator, pki: Pki, tmp_path: Path
) -> None:
    source = tmp_path / "planilla.csv"
    source.write_bytes(CSV)
    signature = _signed(card, pki, source, tmp_path / "planilla.csv.p7m", CadesPackaging.ENVELOPING)
    source.unlink()  # a .p7m carries its content

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _verification(app) is not None)
        page = _verification(app)
        assert page is not None
        yield from wait_until(lambda: _shown(page) == "result", 20)
        assert page.original is None
        assert page.signed_content() == CSV
        assert "Guardar el contenido firmado" in _rows(page.page)
        assert content_name(signature) == "planilla.csv"

    drive(app, script, args=[str(signature)])
    assert content_name(Path("firma.der")) == "firma.der.bin"


def test_a_signed_xml_is_verified_and_can_be_signed_again(
    app: BerignaApplication, card: DnieV2Simulator, pki: Pki, tmp_path: Path
) -> None:
    """An enveloped signature on top would break the one there (ERR-312): the signing page
    offers the other forms."""
    source = tmp_path / "factura.xml"
    source.write_bytes(XML)
    signed = _signed(card, pki, source, tmp_path / "firmada.xml", XadesPackaging.ENVELOPED)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _verification(app) is not None)
        page = _verification(app)
        assert page is not None
        assert page.document.kind is DocumentKind.XML
        yield from wait_until(lambda: _shown(page) == "result", 20)
        assert isinstance(page.verification, XadesVerification)
        assert page._sign.get_visible()
        assert page._sign.get_sensitive()
        page._add_signature()
        yield from wait_until(lambda: _signing(app) is not None)
        signing = _signing(app)
        assert signing is not None
        assert signing.formats is not None
        assert not signing.formats.buttons[XadesPackaging.ENVELOPED].get_sensitive()
        assert signing.packaging() is XadesPackaging.ENVELOPING

    drive(app, script, args=[str(signed)])


def test_an_empty_file_inside_a_p7m_can_be_saved(
    app: BerignaApplication, card: DnieV2Simulator, pki: Pki, tmp_path: Path
) -> None:
    source = tmp_path / "vacio.txt"
    source.write_bytes(b"")
    signature = _signed(card, pki, source, tmp_path / "vacio.txt.p7m", CadesPackaging.ENVELOPING)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _verification(app) is not None)
        page = _verification(app)
        assert page is not None
        yield from wait_until(lambda: _shown(page) == "result", 20)
        assert page.signed_content() == b""

    drive(app, script, args=[str(signature)])
