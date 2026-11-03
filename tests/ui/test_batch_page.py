# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing several files with one PIN in the interface (CU-04; RF-040 to RF-043)."""

import csv
import io
from collections.abc import Generator
from pathlib import Path

import pytest

from berigna.core.batch import Outcome, collect_files
from berigna.core.documents import DocumentKind, inspect_document
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.xades import XadesPackaging
from berigna.core.token.dnie_v2 import INS_VERIFY
from berigna.ui.application import BerignaApplication
from berigna.ui.batch import BatchPage, FormatChoices, display_folder
from conftest import drive, wait_until
from sim.dnie_v2 import DnieV2Simulator
from support.pki import minimal_pdf


def _pdfs(folder: Path, *names: str) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in names:
        path = folder / name
        path.write_bytes(minimal_pdf(name))
        paths.append(path)
    return paths


def _batch(app: BerignaApplication) -> BatchPage:
    assert app.main_window is not None
    assert app.main_window.batch is not None
    return app.main_window.batch


def _shown(page: BatchPage) -> str:
    return str(page._stack.get_visible_child_name())


def test_collect_files(tmp_path: Path) -> None:
    """RF-041: files as given, folders expanded in name order, subfolders on request; a
    folder leaves out hidden files and the signatures berigna writes."""
    [b, a] = _pdfs(tmp_path / "actas", "b.pdf", "A.PDF")
    [deep] = _pdfs(tmp_path / "actas" / "2026", "c.pdf")
    folder = tmp_path / "actas"
    notes = folder / "notas.txt"
    notes.write_text("sí")
    for name in (".oculto", "b.pdf.p7s", "notas.txt.p7m", "acta.xml.xsig"):
        (folder / name).write_bytes(b"x")
    assert collect_files([folder], recursive=False) == [a, b, notes]
    assert collect_files([folder, b], recursive=True) == [deep, a, b, notes]  # b only once
    signature = folder / "b.pdf.p7s"  # never signed again, even when given on its own
    assert collect_files([signature, tmp_path / "no-existe"], recursive=False) == []


def test_folders_are_shown_from_home() -> None:
    assert display_folder(Path.home() / "Documentos" / "actas") == "~/Documentos/actas"
    assert display_folder(Path("/srv/actas")) == "/srv/actas"


def test_sign_a_batch_with_one_pin(
    app: BerignaApplication, card: DnieV2Simulator, tmp_path: Path
) -> None:
    first, second = _pdfs(tmp_path / "uno", "contrato.pdf", "acta.pdf")
    [third] = _pdfs(tmp_path / "dos", "contrato.pdf")  # same name, another folder
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        assert app.main_window is not None
        app.main_window.toast = toasts.append  # type: ignore[method-assign]
        signature = tmp_path / "acta.pdf.p7s"
        signature.write_bytes(b"0")
        app.main_window.sign_batch([first, second, third, tmp_path / "no-existe.pdf", signature])
        page = _batch(app)
        assert not page._sign.get_sensitive()  # while the files are read
        yield from wait_until(lambda: len(page.files) == 3)
        assert [path for path, _sha, _kind in page.files] == [first, second, third]
        assert toasts == [
            "1 archivo no se puede leer; se dejó fuera.",
            "1 firma se dejó fuera: ábrela sola para verificarla.",
        ]
        assert not page.formats.group.get_visible()  # only PDFs: PAdES, nothing to choose
        assert page._sign.get_label() == "_Firmar 3 documentos"
        page.remove(second)
        page.add_paths([second])  # added again, at the end
        yield from wait_until(lambda: len(page.files) == 3)
        page._sign.emit("clicked")
        yield from wait_until(lambda: page.pin_dialog is not None, 10)
        dialog = page.pin_dialog
        assert dialog is not None
        rows = dict(zip(*[iter(_dialog_texts(dialog))] * 2, strict=False))
        assert rows.get("Documentos") == "3 documentos"
        dialog.entry.set_text("123456")
        dialog.sign_button.emit("clicked")
        yield from wait_until(lambda: _shown(page) == "done", 20)
        assert page.items is not None
        assert [item.outcome for item in page.items] == [Outcome.SIGNED] * 3
        assert not page._sign.get_visible()
        report = list(csv.reader(io.StringIO(page.report())))
        assert [row[2] for row in report[1:]] == ["Firmado"] * 3
        page._again()  # the signed documents leave the list
        assert page.files == []
        assert not page._sign.get_sensitive()

    drive(app, script)
    assert card.instructions().count(INS_VERIFY) == 1
    outputs = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*-firmado*.pdf"))
    assert [str(p) for p in outputs] == [
        "dos/contrato-firmado.pdf",
        "uno/acta-firmado.pdf",
        "uno/contrato-firmado.pdf",
    ]
    assert all(inspect_document(tmp_path / p).signatures == 1 for p in outputs)


def test_a_mixed_batch(app: BerignaApplication, card: DnieV2Simulator, tmp_path: Path) -> None:
    """RF-041: PAdES for the PDF, XAdES for the XML and CAdES for the rest, each in the
    packaging chosen for its kind, with one PIN."""
    [pdf] = _pdfs(tmp_path, "contrato.pdf")
    xml = tmp_path / "factura.xml"
    xml.write_bytes(b"<factura><total>100</total></factura>")
    other = tmp_path / "planilla.csv"
    other.write_bytes(b"nombre;monto\nRosa;100\n")
    signed_xml = tmp_path / "firmada.xml"  # already signed: enveloped would break it (ERR-312)
    signed_xml.write_bytes(b'<a><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></a>')

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        assert app.main_window is not None
        app.main_window.sign_batch([pdf, xml, other, signed_xml])
        page = _batch(app)
        yield from wait_until(lambda: len(page.files) == 4)
        kinds = [kind for _path, _sha, kind in page.files]
        assert kinds == [DocumentKind.PDF, DocumentKind.XML, DocumentKind.OTHER, DocumentKind.XML]
        assert page.formats.group.get_visible()
        assert page.formats.xml.get_visible()
        assert page.formats.other.get_visible()
        assert page.formats.packaging(DocumentKind.XML) is XadesPackaging.ENVELOPED
        assert "Firma Perú" not in page.formats.other.get_subtitle()
        page.formats.other.set_selected(FormatChoices.OTHER.index(CadesPackaging.ENVELOPING))
        assert "Firma Perú no reconoce la extensión .p7m" in page.formats.other.get_subtitle()
        page.formats.xml.set_selected(FormatChoices.XML.index(XadesPackaging.DETACHED))
        assert "Firma Perú no valida firmas .xsig" in page.formats.xml.get_subtitle()
        page.formats.xml.set_selected(FormatChoices.XML.index(XadesPackaging.ENVELOPED))
        page._sign.emit("clicked")
        yield from wait_until(lambda: page.pin_dialog is not None, 10)
        dialog = page.pin_dialog
        assert dialog is not None
        dialog.entry.set_text("123456")
        dialog.sign_button.emit("clicked")
        yield from wait_until(lambda: _shown(page) == "done", 30)
        assert page.items is not None
        outcomes = [item.outcome for item in page.items]
        assert outcomes == [Outcome.SIGNED, Outcome.SIGNED, Outcome.SIGNED, Outcome.FAILED]
        assert page.items[3].code == "ERR-312"  # reported before the PIN, the rest went on

    drive(app, script)
    assert card.instructions().count(INS_VERIFY) == 1
    assert inspect_document(tmp_path / "contrato-firmado.pdf").signatures == 1
    assert inspect_document(tmp_path / "factura-firmado.xml").signatures == 1
    enveloping = inspect_document(tmp_path / "planilla.csv.p7m")
    assert (enveloping.kind, enveloping.signatures) == (DocumentKind.CADES, 1)
    assert not (tmp_path / "firmada-firmado.xml").exists()


def test_several_files_open_a_batch(app: BerignaApplication, tmp_path: Path) -> None:
    paths = _pdfs(tmp_path, "uno.pdf", "dos.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.main_window is not None and app.main_window.batch)
        yield from wait_until(lambda: len(_batch(app).files) == 2)
        assert [path for path, _sha, _kind in _batch(app).files] == paths

    drive(app, script, args=[str(p) for p in paths])


def test_a_folder_opens_a_batch(app: BerignaApplication, tmp_path: Path) -> None:
    paths = _pdfs(tmp_path / "carpeta", "a.pdf", "b.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.main_window is not None and app.main_window.batch)
        yield from wait_until(lambda: len(_batch(app).files) == 2)
        assert [path for path, _sha, _kind in _batch(app).files] == paths

    drive(app, script, args=[str(tmp_path / "carpeta")])


def test_cancelling_the_pin_signs_nothing(app: BerignaApplication, tmp_path: Path) -> None:
    paths = _pdfs(tmp_path, "uno.pdf", "dos.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        assert app.main_window is not None
        app.main_window.sign_batch(paths)
        page = _batch(app)
        page._sign.emit("clicked")  # too early: the files are still being read
        assert page.pin_dialog is None
        yield from wait_until(lambda: page._sign.get_sensitive())
        page._sign.emit("clicked")
        yield from wait_until(lambda: page.pin_dialog is not None, 10)
        assert page.pin_dialog is not None
        page.pin_dialog.close()
        yield from wait_until(lambda: _shown(page) == "form", 10)
        assert page._sign.get_sensitive()

    drive(app, script)
    assert not list(tmp_path.glob("*-firmado.pdf"))


def _dialog_texts(dialog: object) -> list[str]:
    """Title and subtitle of every row of the PIN dialog's summary."""
    from gi.repository import Adw, Gtk

    texts: list[str] = []
    stack: list[Gtk.Widget] = [dialog]  # type: ignore[list-item]
    while stack:
        widget = stack.pop(0)
        if isinstance(widget, Adw.ActionRow):
            texts += [widget.get_title(), widget.get_subtitle()]
        child = widget.get_first_child()
        while child is not None:
            stack.append(child)
            child = child.get_next_sibling()
    return texts


def test_files_left_by_a_cancel_are_in_the_history(
    app: BerignaApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RF-082: what the batch did not sign is recorded too, with ERR-309."""
    import berigna.core.batch as core_batch

    paths = _pdfs(tmp_path, "uno.pdf", "dos.pdf", "tres.pdf")
    real = core_batch.sign_checked

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        assert app.main_window is not None
        app.main_window.sign_batch(paths)
        page = _batch(app)

        def then_cancel(job: object, **kwargs: object) -> object:
            result = real(job, **kwargs)  # type: ignore[arg-type]
            page._cancel.set()  # as the Cancel button does, after the first file
            return result

        monkeypatch.setattr(core_batch, "sign_checked", then_cancel)
        yield from wait_until(lambda: page._sign.get_sensitive())
        page._sign.emit("clicked")
        yield from wait_until(lambda: page.pin_dialog is not None, 10)
        assert page.pin_dialog is not None
        page.pin_dialog.entry.set_text("123456")
        page.pin_dialog.sign_button.emit("clicked")
        yield from wait_until(lambda: _shown(page) == "done", 20)
        history = app.main_window.services.history()
        assert history is not None
        entries = sorted(history.entries(), key=lambda e: e.file_name)
        assert [(e.file_name, e.result, e.detail) for e in entries] == [
            ("dos.pdf", "error", "ERR-309"),
            ("tres.pdf", "error", "ERR-309"),
            ("uno.pdf", "ok", "revocation-unchecked"),
        ]

    drive(app, script)
