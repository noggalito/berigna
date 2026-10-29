# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing several PDFs with one PIN in the interface (CU-04; RF-040 to RF-043)."""

import csv
import io
from collections.abc import Generator
from pathlib import Path

from berigna.core.batch import Outcome
from berigna.core.documents import inspect_document
from berigna.core.token.dnie_v2 import INS_VERIFY
from berigna.ui.application import BerignaApplication
from berigna.ui.batch import BatchPage, collect_pdfs, display_folder
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


def test_collect_pdfs(tmp_path: Path) -> None:
    """RF-041: files as given, folders expanded in name order, subfolders on request."""
    [b, a] = _pdfs(tmp_path / "actas", "b.pdf", "A.PDF")
    [deep] = _pdfs(tmp_path / "actas" / "2026", "c.pdf")
    (tmp_path / "actas" / "notas.txt").write_text("no")
    folder = tmp_path / "actas"
    assert collect_pdfs([folder], recursive=False) == [a, b]
    assert collect_pdfs([folder, b], recursive=True) == [deep, a, b]  # b only once
    assert collect_pdfs([tmp_path / "actas" / "notas.txt"], recursive=False) == []


def test_folders_are_shown_from_home() -> None:
    assert display_folder(Path.home() / "Documentos" / "actas") == "~/Documentos/actas"
    assert display_folder(Path("/srv/actas")) == "/srv/actas"


def test_sign_a_batch_with_one_pin(
    app: BerignaApplication, card: DnieV2Simulator, tmp_path: Path
) -> None:
    first, second = _pdfs(tmp_path / "uno", "contrato.pdf", "acta.pdf")
    [third] = _pdfs(tmp_path / "dos", "contrato.pdf")  # same name, another folder
    note = tmp_path / "nota.txt"
    note.write_text("no es un PDF")
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        assert app.main_window is not None
        app.main_window.toast = toasts.append  # type: ignore[method-assign]
        app.main_window.sign_batch([first, second, third, note])
        page = _batch(app)
        assert [path for path, _sha in page.files] == [first, second, third]
        assert toasts == ["1 archivo no es PDF o no se puede leer; se dejó fuera."]
        assert page._sign.get_label() == "_Firmar 3 documentos"
        page.remove(second)
        page.add_paths([second])  # added again, at the end
        page._sign.emit("clicked")
        yield from wait_until(lambda: page.pin_dialog is not None, 10)
        dialog = page.pin_dialog
        assert dialog is not None
        rows = dict(zip(*[iter(_dialog_texts(dialog))] * 2, strict=False))
        assert rows.get("Documentos") == "3 documentos PDF"
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


def test_several_files_open_a_batch(app: BerignaApplication, tmp_path: Path) -> None:
    paths = _pdfs(tmp_path, "uno.pdf", "dos.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.main_window is not None and app.main_window.batch)
        assert [path for path, _sha in _batch(app).files] == paths

    drive(app, script, args=[str(p) for p in paths])


def test_a_folder_opens_a_batch(app: BerignaApplication, tmp_path: Path) -> None:
    paths = _pdfs(tmp_path / "carpeta", "a.pdf", "b.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.main_window is not None and app.main_window.batch)
        assert [path for path, _sha in _batch(app).files] == paths

    drive(app, script, args=[str(tmp_path / "carpeta")])


def test_cancelling_the_pin_signs_nothing(app: BerignaApplication, tmp_path: Path) -> None:
    paths = _pdfs(tmp_path, "uno.pdf", "dos.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        assert app.main_window is not None
        app.main_window.sign_batch(paths)
        page = _batch(app)
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
