# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
import datetime as dt
import json
import threading
from collections.abc import Generator
from pathlib import Path

import pytest
from gi.repository import Adw, Gio, Gtk

from berigna.core.errors import TrustStoreIntegrityError
from berigna.core.i18n import Language
from berigna.core.trust import TrustStore
from berigna.core.validation import Indication, PdfVerification
from berigna.core.validation.pdf import TimestampReport
from berigna.ui import i18n
from berigna.ui.application import BerignaApplication
from berigna.ui.verification import VerificationPage
from conftest import FakeReaders, drive, wait_until
from support.pki import Pki, minimal_pdf
from support.signed import sign, signed_with_revinfo


def _page(app: BerignaApplication) -> VerificationPage:
    assert app.main_window is not None
    assert app.main_window.verification is not None
    return app.main_window.verification


def _shown(app: BerignaApplication) -> str:
    if app.main_window is None or app.main_window.verification is None:
        return ""
    return str(_page(app)._stack.get_visible_child_name())


def _summary(app: BerignaApplication) -> str:
    return str(_page(app).summary_row.get_title())


def _file(tmp_path: Path, data: bytes, name: str = "firmado.pdf") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_valid_signature_and_reports(app: BerignaApplication, pki: Pki, tmp_path: Path) -> None:
    data = signed_with_revinfo(pki)
    path = _file(tmp_path, data)
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "result")
        page = _page(app)
        assert _summary(app) == (
            "1 firma válida · El documento no fue modificado después de la última firma."
        )
        assert page._export.get_sensitive()
        assert not page._retry.get_visible()
        assert page.page.get_title() == "firmado.pdf"
        assert app.main_window is not None
        app.main_window.toast = toasts.append  # type: ignore[method-assign]

        report = json.loads(page.report("json"))
        assert report["signatures"][0]["indication"] == "TOTAL-PASSED"
        for kind in ("pdf-es", "pdf-quz"):
            assert page.report(kind).startswith(b"%PDF")

        target = tmp_path / "informe.json"
        target.write_bytes(b"anterior")  # the save dialog already asked to replace it
        page.save(target, page.report("json"))
        assert json.loads(target.read_bytes())["file"]["name"] == "firmado.pdf"
        page.save(tmp_path / "no-existe" / "x.json", b"{}")

        revision = page.signed_revision(1)
        assert data.startswith(revision)
        assert revision.rstrip().endswith(b"%%EOF")

    drive(app, script, args=[str(path)])
    assert toasts == ["Se guardó informe.json", "No se pudo guardar x.json."]


def _walk(widget: Gtk.Widget) -> Generator[Gtk.Widget, None, None]:
    child = widget.get_first_child()
    while child is not None:
        yield child
        yield from _walk(child)
        child = child.get_next_sibling()


def _spanish_button(app: BerignaApplication) -> Gtk.Button | None:
    """The "Ver en español" button of the summary, labelled in Quechua."""
    for child in _walk(_page(app).summary_row):
        if isinstance(child, Gtk.Button) and child.get_label() == "Kastilla simipi qhaway":
            return child
    return None


def test_result_in_quechua_offers_spanish(
    app: BerignaApplication, pki: Pki, tmp_path: Path
) -> None:
    path = _file(tmp_path, signed_with_revinfo(pki))

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "result")
        assert _spanish_button(app) is None  # only in Quechua
        assert app.settings is not None
        app.settings.set_string("ui-language", "quz_PE")
        yield from wait_until(lambda: _shown(app) == "result" and _spanish_button(app) is not None)
        button = _spanish_button(app)
        assert button is not None
        button.emit("clicked")  # "Ver en español", in Quechua
        yield
        dialog = _page(app).show_spanish()
        assert dialog.get_heading() == "firmado.pdf"
        assert dialog.get_body().startswith("1 firma válida · ")
        assert "La firma es válida." in dialog.get_body()
        dialog.force_close()
        assert i18n.current_language() is Language.QUZ_PE
        app.settings.set_string("ui-language", "es_PE")
        yield from wait_until(lambda: i18n.current_language() is Language.ES_PE)

    drive(app, script, args=[str(path)])


def test_indeterminate_result_can_be_verified_again(
    app: BerignaApplication, pki: Pki, tmp_path: Path
) -> None:
    signed, _leaf = sign(pki, minimal_pdf())
    path = _file(tmp_path, signed)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "result")
        page = _page(app)
        assert _summary(app).startswith("1 firma no se pudo verificar")
        assert page._retry.get_visible()
        page.page.activate_action("verification.verify-again", None)
        assert _shown(app) == "loading"
        assert not page._export.get_sensitive()
        yield from wait_until(lambda: _shown(app) == "result")

    drive(app, script, args=[str(path)])


def test_result_of_a_document_left_behind_is_dropped(
    readers: FakeReaders, pki: Pki, tmp_path: Path
) -> None:
    release = threading.Event()

    def slow_store() -> TrustStore:
        release.wait(5)
        return pki.store

    app = BerignaApplication(
        status_source=lambda: readers, trust_store=slow_store, online=False, unique=False
    )
    signed = _file(tmp_path, signed_with_revinfo(pki))
    plain = _file(tmp_path, minimal_pdf(), "sin-firmas.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "loading")
        old = _page(app)
        assert app.main_window is not None
        window = app.main_window
        window.open_file(Gio.File.new_for_path(str(plain)))
        yield from wait_until(lambda: window.verification is None)
        release.set()
        for _ in range(25):  # time for the worker thread and its idle callback
            yield
        assert old._stack.get_child_by_name("result") is None

    drive(app, script, args=[str(signed)])


def test_verification_errors_are_shown(readers: FakeReaders, pki: Pki, tmp_path: Path) -> None:
    def broken_store() -> TrustStore:
        raise TrustStoreIntegrityError("manifest mismatch")

    app = BerignaApplication(
        status_source=lambda: readers, trust_store=broken_store, online=False, unique=False
    )
    path = _file(tmp_path, signed_with_revinfo(pki))

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "error")
        error: Adw.StatusPage = _page(app)._stack.get_child_by_name("error")
        assert error.get_title() == "No se pudo verificar el documento"
        path.unlink()
        _page(app).start()
        yield from wait_until(lambda: "No se pudo abrir" in _error_text(app))

    drive(app, script, args=[str(path)])


def _error_text(app: BerignaApplication) -> str:
    error = _page(app)._stack.get_child_by_name("error")
    return str(error.get_description()) if error is not None else ""


def test_document_timestamps_are_listed(app: BerignaApplication, pki: Pki, tmp_path: Path) -> None:
    path = _file(tmp_path, signed_with_revinfo(pki))
    when = dt.datetime(2026, 10, 27, 15, 30, tzinfo=dt.UTC)
    stamp = TimestampReport(Indication.TOTAL_PASSED, None, when, pki.ca, "Sello1")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "result")
        page = _page(app)
        assert page.verification is not None
        verification = PdfVerification(page.verification.signatures, (stamp,), when)
        page._show_result(path.read_bytes(), verification, pki.store)
        result = page._stack.get_child_by_name("result")
        titles = []
        widget = result
        stack = [widget]
        while stack:
            widget = stack.pop()
            if isinstance(widget, Adw.PreferencesGroup):
                titles.append(widget.get_title())
            child = widget.get_first_child()
            while child is not None:
                stack.append(child)
                child = child.get_next_sibling()
        assert "Sellos de tiempo de documento" in titles

    drive(app, script, args=[str(path)])


def test_reports_need_a_result(app: BerignaApplication, pki: Pki, tmp_path: Path) -> None:
    path = _file(tmp_path, signed_with_revinfo(pki))

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "result")
        page = _page(app)
        page.verification = None
        with pytest.raises(RuntimeError):
            page.report("json")
        with pytest.raises(RuntimeError):
            page.signed_revision(1)

    drive(app, script, args=[str(path)])


def test_unexpected_verification_errors_are_shown(
    readers: FakeReaders, pki: Pki, tmp_path: Path
) -> None:
    def broken_store() -> TrustStore:
        raise RuntimeError("bug")

    app = BerignaApplication(
        status_source=lambda: readers, trust_store=broken_store, online=False, unique=False
    )
    path = _file(tmp_path, signed_with_revinfo(pki))

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _shown(app) == "error")
        assert _error_text(app) == "Error inesperado."

    drive(app, script, args=[str(path)])
