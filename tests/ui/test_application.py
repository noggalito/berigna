# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
from collections.abc import Generator
from pathlib import Path

import pytest
from gi.repository import Adw, Gdk, Gio

from berigna import main as entry
from berigna.core.i18n import Language
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
        # Pending Quechua strings fall back to Spanish, so the notice is shown once.
        assert _banner(app).get_title() == notice
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


def test_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
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
    names |= {"open-menu-symbolic", "pe.berigna.Berigna", "pe.berigna.Berigna-symbolic"}
    # The application icons come from the resources, as GtkApplication registers them.
    theme.add_resource_path("/pe/berigna/Berigna/icons")
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
    app.settings = Gio.Settings.new("pe.berigna.Berigna")
    app.settings.set_string("tsa-url", url)
    try:
        assert (app._configured_timestamper() is not None) is configured
    finally:
        app.settings.reset("tsa-url")
