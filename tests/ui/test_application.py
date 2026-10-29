# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
from collections.abc import Generator
from pathlib import Path

import pytest
from gi.repository import Adw, Gdk, Gio

from berigna import main as entry
from berigna.core import crashes
from berigna.core.i18n import Language
from berigna.core.logs import log_directory
from berigna.core.token.dnie_v2 import DNIE_V2_ATR
from berigna.core.token.monitor import ReaderState
from berigna.ui import i18n, presentation
from berigna.ui.application import BerignaApplication
from berigna.ui.window import MainWindow
from conftest import FakeReaders, drive, wait_until
from support.pki import minimal_pdf


def _window(app: BerignaApplication) -> MainWindow:
    assert app.main_window is not None
    return app.main_window


def _visible_title(app: BerignaApplication) -> str:
    navigation: Adw.NavigationView = _window(app)._navigation
    return str(navigation.get_visible_page().get_title())


def _status(app: BerignaApplication) -> str:
    return str(_window(app)._status_label.get_label())


def _pdf(tmp_path: Path, name: str = "contrato.pdf") -> Path:
    path = tmp_path / name
    path.write_bytes(minimal_pdf())
    return path


def test_status_bar_follows_the_card(app: BerignaApplication, readers: FakeReaders) -> None:
    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: _status(app) == "Conecta un lector de tarjetas")
        readers.current = (ReaderState("Lector", None),)
        yield from wait_until(lambda: _status(app) == "Inserta tu DNIe en el lector")
        readers.current = (ReaderState("Lector", DNIE_V2_ATR),)
        yield from wait_until(lambda: _status(app) == "DNIe listo")

    drive(app, script)
    assert readers.closed  # the monitor stopped with the application


def test_open_from_the_command_line(app: BerignaApplication, tmp_path: Path) -> None:
    path = _pdf(tmp_path)

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.main_window is not None)
        yield from wait_until(lambda: _visible_title(app) == "contrato.pdf")
        assert _window(app).signing is not None  # a PDF without signatures is for signing
        document = _window(app).document
        assert document is not None
        assert document.path == path

    drive(app, script, args=[str(path)])


def test_drop_a_file_and_open_another(app: BerignaApplication, tmp_path: Path) -> None:
    first, second = _pdf(tmp_path, "uno.pdf"), _pdf(tmp_path, "dos.pdf")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        window = _window(app)
        files = Gdk.FileList.new_from_list([Gio.File.new_for_path(str(first))])
        assert window._on_drop(None, files, 0, 0)
        yield from wait_until(lambda: _visible_title(app) == "uno.pdf")
        window.open_file(Gio.File.new_for_path(str(second)))
        yield from wait_until(lambda: _visible_title(app) == "dos.pdf")
        # Opening replaces the document page instead of stacking them.
        assert window._navigation.get_navigation_stack().get_n_items() == 2

    drive(app, script)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"%PDF-1.7 roto", "roto.pdf: El archivo no es un documento que berigna pueda leer"),
        (None, "No se pudo abrir roto.pdf."),
    ],
)
def test_files_that_cannot_be_opened(
    app: BerignaApplication, tmp_path: Path, content: bytes | None, message: str
) -> None:
    path = tmp_path / "roto.pdf"
    if content is not None:
        path.write_bytes(content)
    toasts: list[str] = []
    done: list[bool] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        window = _window(app)
        window.toast = toasts.append  # type: ignore[method-assign]
        window.open_file(Gio.File.new_for_path(str(path)), lambda: done.append(True))
        yield from wait_until(lambda: bool(done))
        window.open_file(Gio.File.new_for_uri("https://example.org/x.pdf"))
        assert window.document is None
        assert _visible_title(app) == "berigna"

    drive(app, script)
    assert toasts[0].startswith(message)
    assert toasts[1] == "Solo se pueden abrir archivos de este equipo."


def test_quechua_shows_the_notice_and_can_switch_to_spanish(
    app: BerignaApplication, tmp_path: Path
) -> None:
    path = _pdf(tmp_path)
    notice = "Traducción sin revisar por hablantes. En caso de duda, prevalece el texto en español."

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.main_window is not None)
        yield from wait_until(lambda: _visible_title(app) == "contrato.pdf")
        assert app.settings is not None
        assert not _banner(app).get_revealed()
        app.settings.set_string("ui-language", "quz_PE")
        assert i18n.current_language() is Language.QUZ_PE
        assert _banner(app).get_revealed()
        # The notice in Quechua and in Spanish, which prevails (DP-14).
        assert _banner(app).get_title() == (
            "Rimaqkunaq mana qhawasqan t'ikrasqa. Iskayrayaspaqa kastilla simipi qillqasqan "
            f"atipan. · {notice}"
        )
        yield from wait_until(lambda: _visible_title(app) == "contrato.pdf")
        old = app.main_window
        app.activate_action("show-in-spanish", None)
        assert i18n.current_language() is Language.ES_PE
        assert app.main_window is not old
        assert not _banner(app).get_revealed()
        # The document is opened again in the rebuilt window.
        yield from wait_until(lambda: _visible_title(app) == "contrato.pdf")

    drive(app, script, args=[str(path)])


def _banner(app: BerignaApplication) -> Adw.Banner:
    return _window(app)._banner


def test_about(app: BerignaApplication) -> None:
    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.main_window is not None)
        app.activate_action("about", None)
        yield
        assert _window(app).window.get_visible_dialog() is not None

    drive(app, script)


def test_a_failure_of_the_last_run_is_offered_once(app: BerignaApplication) -> None:
    """R-DES-11: the pending report is offered once, can be copied, and is then gone."""
    pending = log_directory() / crashes.PENDING_NAME
    pending.parent.mkdir(parents=True, exist_ok=True)
    pending.write_text("[main thread]\nTraceback\nRuntimeError: FIR 12345678 hard\n")
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        app.activate()
        yield from wait_until(lambda: app.failure_dialog is not None)
        dialog = app.failure_dialog
        assert dialog is not None
        assert dialog.get_heading() == "berigna tuvo un fallo inesperado la última vez"
        assert "https://github.com/noggalito/berigna/issues" in dialog.get_body()
        assert "carpetas" in dialog.get_body()  # warns that paths may appear
        assert pending.exists()  # removed only once the user has answered
        _window(app).toast = toasts.append  # type: ignore[method-assign]
        dialog.emit("response", "copy")
        clipboard = Gdk.Display.get_default().get_clipboard()
        copied: list[str] = []
        clipboard.read_text_async(None, lambda c, r: copied.append(c.read_text_finish(r)))
        yield from wait_until(lambda: bool(copied))
        assert not pending.exists()
        assert copied[0].startswith("Informe de fallo de berigna ")
        assert "RuntimeError: FIR ****5678 hard" in copied[0]
        dialog.force_close()
        app.failure_dialog = None
        app.activate()  # only once per run
        yield
        assert app.failure_dialog is None

    drive(app, script)
    assert toasts == ["Informe copiado. No incluye el PIN, y el DNI va enmascarado."]


def test_entry_point_installs_the_failure_record(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    installed: list[bool] = []
    monkeypatch.setattr(crashes, "install", lambda: installed.append(True))
    monkeypatch.setattr(BerignaApplication, "run", lambda self, argv: 0)
    assert entry.main(["berigna"]) == 0
    assert installed == [True]

    def broken() -> None:
        raise PermissionError("pending-failure.txt")

    monkeypatch.setattr(crashes, "install", broken)
    assert entry.main(["berigna"]) == 0  # berigna still starts
    assert "berigna: no record of failures" in capsys.readouterr().err


def test_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(crashes, "install", lambda: None)  # not the hooks of the test process
    monkeypatch.setattr(BerignaApplication, "run", lambda self, argv: 0)
    assert entry.main(["berigna"]) == 0
    monkeypatch.delenv("BERIGNA_RESOURCES")
    assert entry.main(["berigna"]) == 1


def test_every_icon_exists_in_the_theme() -> None:
    """A missing symbolic icon shows as an empty box, and no other test would notice."""
    from gi.repository import Gdk, Gtk

    theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
    names = set(presentation.ICONS)
    names |= {icon for icon, _style in presentation._INDICATION_ICONS.values()}
    names |= {icon for icon, _message in presentation._DEVICE.values()}
    names |= {"open-menu-symbolic", "com.noggalito.Berigna", "com.noggalito.Berigna-symbolic"}
    # The application icons come from the resources, as GtkApplication registers them.
    theme.add_resource_path("/com/noggalito/Berigna/icons")
    assert [name for name in sorted(names) if not theme.has_icon(name)] == []


def test_files_that_are_not_pdf(app: BerignaApplication, tmp_path: Path) -> None:
    path = tmp_path / "datos.xml"
    path.write_bytes(b"<datos/>")

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.main_window is not None)
        yield from wait_until(lambda: _visible_title(app) == "datos.xml")
        page = _window(app)._navigation.get_visible_page().get_child().get_content()
        assert page.get_description().startswith("<b>berigna</b> todavía no puede firmar")

    drive(app, script, args=[str(path)])


@pytest.mark.parametrize(
    ("url", "configured"),
    [("", False), ("https://tsa.example", True), ("ftp://tsa.example", False)],
)
def test_tsa_comes_from_the_preferences(url: str, configured: bool) -> None:
    app = BerignaApplication(unique=False)
    app.settings = Gio.Settings.new("com.noggalito.Berigna")
    app.settings.set_string("tsa-url", url)
    try:
        assert (app._configured_timestamper() is not None) is configured
    finally:
        app.settings.reset("tsa-url")
