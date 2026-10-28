# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Preferences (CU-08): general, network and trust; the trusted list in the application."""

from collections.abc import Generator
from pathlib import Path

import pytest

from berigna.core.errors import TslError
from berigna.core.net import proxy
from berigna.core.trust import TrustStore
from berigna.core.trust.cache import TslCache
from berigna.core.trust.tsl import TrustedList, load_tsl
from berigna.ui.application import BerignaApplication
from berigna.ui.preferences import PreferencesDialog
from conftest import FakeReaders, drive, wait_until
from support.pki import Pki
from support.tsa import make_timestamper
from support.tsl import Service, TslContent, TslPki, build_tsl, build_tsl_pki


@pytest.fixture(scope="module")
def tsl_pki() -> TslPki:
    return build_tsl_pki()


@pytest.fixture(autouse=True)
def environment(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """The proxy goes to a fake environment, never to the one of the test process."""
    fake: dict[str, str] = {}
    monkeypatch.setattr(proxy, "process_environment", lambda: fake)
    return fake


def _preferences(app: BerignaApplication) -> PreferencesDialog:
    assert app.preferences is not None
    return app.preferences


def _open(app: BerignaApplication) -> Generator[None, None, PreferencesDialog]:
    app.activate()
    yield from wait_until(lambda: app.main_window is not None)
    app.activate_action("preferences", None)
    yield from wait_until(lambda: app.preferences is not None)
    return _preferences(app)


def test_general_preferences(app: BerignaApplication, tmp_path: Path) -> None:
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        dialog = yield from _open(app)
        dialog.toast = toasts.append  # type: ignore[method-assign]
        settings = app.settings
        assert settings is not None
        dialog.level.set_selected(3)  # Basic
        assert settings.get_string("default-level") == "B-B"
        dialog.digest.set_selected(2)
        assert settings.get_string("digest-algorithm") == "sha512"
        dialog.suffix.set_text("-con-firma")
        dialog.suffix.emit("apply")
        assert settings.get_string("output-suffix") == "-con-firma"
        dialog.suffix.set_text("a/b")
        dialog.suffix.emit("apply")
        assert settings.get_string("output-suffix") == "-con-firma"
        dialog.set_folder(str(tmp_path))
        assert dialog.folder.get_subtitle() == str(tmp_path)
        assert dialog.folder_reset.get_visible()
        dialog.folder_reset.emit("clicked")
        assert settings.get_string("output-directory") == ""
        assert dialog.folder.get_subtitle() == "La misma carpeta que el original"
        for key in ("default-level", "digest-algorithm", "output-suffix"):
            settings.reset(key)

    drive(app, script)
    assert toasts == ["El sufijo no puede estar vacío ni contener «/»."]


def test_changing_the_language_keeps_the_preferences_open(app: BerignaApplication) -> None:
    def script(app: BerignaApplication) -> Generator[None, None, None]:
        dialog = yield from _open(app)
        old_window = app.main_window
        dialog.language.set_selected(2)  # Runasimi
        assert app.main_window is not old_window
        assert app.preferences is not None
        assert app.preferences is not dialog
        assert app.settings is not None
        assert app.settings.get_string("ui-language") == "quz_PE"
        app.settings.reset("ui-language")

    drive(app, script)


def test_network_preferences(app: BerignaApplication, environment: dict[str, str]) -> None:
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        dialog = yield from _open(app)
        dialog.toast = toasts.append  # type: ignore[method-assign]
        settings = app.settings
        assert settings is not None
        dialog.test_tsa()  # nothing configured yet
        dialog.tsa_url.set_text("ftp://tsa.example")
        dialog.tsa_url.emit("apply")
        dialog.tsa_url.set_text("https://tsa.example/tsp")
        dialog.tsa_url.emit("apply")
        assert settings.get_string("tsa-url") == "https://tsa.example/tsp"
        settings.reset("tsa-url")

        assert not dialog.proxy_url.get_sensitive()
        dialog.proxy.set_selected(1)  # manual
        assert dialog.proxy_url.get_sensitive()
        dialog.proxy_url.set_text("socks5://x:1")
        dialog.proxy_url.emit("apply")
        dialog.proxy_url.set_text("http://proxy.example:3128")
        dialog.proxy_url.emit("apply")
        assert environment["https_proxy"] == "http://proxy.example:3128"
        dialog.proxy.set_selected(2)  # none
        assert environment["NO_PROXY"] == "*"
        settings.set_string("proxy-url", "no-es-una-url")
        settings.set_string("proxy-mode", "manual")  # invalid: the system proxy is used
        assert "NO_PROXY" not in environment
        for key in ("proxy-mode", "proxy-url"):
            settings.reset(key)

    drive(app, script)
    assert toasts == [
        "No hay ninguna autoridad de sellado de tiempo configurada.",
        "La dirección debe empezar por http:// o https://.",
        "La dirección del proxy debe empezar por http:// o https://.",
    ]


def test_tsa_test_button(readers: FakeReaders, pki: Pki) -> None:
    stamper, _cert = make_timestamper(pki)
    app = BerignaApplication(
        status_source=lambda: readers,
        trust_store=lambda: pki.store,
        timestamper=lambda: stamper,
        online=False,
        unique=False,
    )
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        dialog = yield from _open(app)
        dialog.toast = toasts.append  # type: ignore[method-assign]
        dialog.test_tsa()
        assert not dialog.tsa_test.get_sensitive()
        yield from wait_until(lambda: bool(toasts), 10)
        assert dialog.tsa_test.get_sensitive()

    drive(app, script)
    assert toasts == ["La autoridad de sellado de tiempo respondió con un sello válido."]


def _download(tsl_pki: TslPki, pki: Pki, fail: list[bool]):  # type: ignore[no-untyped-def]
    data = build_tsl(tsl_pki, TslContent(sequence=7, services=[Service(pki.ca)]))

    def download(minimum: int | None) -> tuple[TrustedList, bytes]:
        if fail:
            raise TslError("offline")
        return load_tsl(data, minimum_sequence=minimum, root=tsl_pki.root), data

    return download


def test_trusted_list_extends_the_store(
    readers: FakeReaders, pki: Pki, tsl_pki: TslPki, tmp_path: Path
) -> None:
    fail: list[bool] = []
    app = BerignaApplication(
        status_source=lambda: readers,
        tsl_cache=TslCache(tmp_path, root=tsl_pki.root),
        tsl_download=_download(tsl_pki, pki, fail),
        online=False,
        unique=False,
    )
    toasts: list[str] = []

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.tsl is not None, 10)
        bundled = len(TrustStore.load_bundled().entries)
        assert len(app._trust_store().entries) == bundled + 1  # the CA of the list
        dialog = yield from _open(app)
        dialog.toast = toasts.append  # type: ignore[method-assign]
        assert dialog.tsl_row.get_title().startswith("Lista 7, emitida el ")
        dialog.update_tsl()
        assert dialog.tsl_row.get_title() == "Comprobando la lista de confianza…"
        yield from wait_until(lambda: len(toasts) == 1, 10)
        fail.append(True)
        dialog.update_tsl()
        yield from wait_until(lambda: len(toasts) == 2, 10)
        # Offline, the cached list stays in use.
        assert dialog.tsl_row.get_title().startswith("Lista 7")

    drive(app, script)
    assert toasts == [
        "La lista de confianza está al día.",
        "No se pudo actualizar la lista de confianza.",
    ]


def test_without_a_trusted_list(
    readers: FakeReaders, pki: Pki, tsl_pki: TslPki, tmp_path: Path
) -> None:
    app = BerignaApplication(
        status_source=lambda: readers,
        tsl_cache=TslCache(tmp_path, root=tsl_pki.root),
        tsl_download=_download(tsl_pki, pki, [True]),
        unique=False,
    )

    def script(app: BerignaApplication) -> Generator[None, None, None]:
        yield from wait_until(lambda: app.tsl is not None, 10)
        dialog = yield from _open(app)
        assert dialog.tsl_row.get_title() == "No disponible"
        assert len(app._trust_store().entries) == len(TrustStore.load_bundled().entries)

    drive(app, script)


def test_default_cache_lives_in_the_user_data_folder() -> None:
    app = BerignaApplication(unique=False)
    assert app.tsl_cache().directory.parts[-2:] == ("berigna", "tsl")
