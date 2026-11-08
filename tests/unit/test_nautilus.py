# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The Nautilus extension (RF-070) with fake Nautilus, Gio and GObject bindings.

python3-nautilus is not installed where the suite runs; the extension is exercised through
the same interfaces it uses inside Nautilus: the provider builds menu items for a selection
and the items launch berigna with the URIs of the files.
"""

import importlib
import sys
import types
from collections.abc import Callable, Sequence
from typing import Any, ClassVar

import pytest


class _FakeFile:
    def __init__(
        self,
        uri: str = "file:///home/prueba/acta.pdf",
        *,
        scheme: str = "file",
        directory: bool = False,
    ) -> None:
        self._uri = uri
        self._scheme = scheme
        self._directory = directory

    def get_uri(self) -> str:
        return self._uri

    def get_uri_scheme(self) -> str:
        return self._scheme

    def is_directory(self) -> bool:
        return self._directory


class _FakeMenuItem:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.connected: list[tuple[str, Callable[..., object], tuple[object, ...]]] = []

    def connect(self, signal: str, callback: Callable[..., object], *args: object) -> None:
        self.connected.append((signal, callback, args))


class _FakeDesktopAppInfo:
    launched: ClassVar[list[list[str]]] = []

    def launch_uris(self, uris: Sequence[str], _context: object) -> None:
        self.launched.append(list(uris))


class _FakeGio:
    class DesktopAppInfo:
        new_calls: ClassVar[list[str]] = []
        result: ClassVar[_FakeDesktopAppInfo | None] = _FakeDesktopAppInfo()

        @classmethod
        def new(cls, app_id: str) -> _FakeDesktopAppInfo | None:
            cls.new_calls.append(app_id)
            return cls.result


class _FakeGObject:
    class GObject:
        pass


class _FakeNautilus:
    class MenuProvider:
        pass

    MenuItem = _FakeMenuItem


_AVAILABLE = {"4.1"}  # the Nautilus API versions of the fake system


def _require_version(_name: str, version: str) -> None:
    _REQUESTED.append(version)
    if version not in _AVAILABLE:
        raise ValueError(f"Namespace Nautilus not available for version {version}")


_REQUESTED: list[str] = []


def _install_fake_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    gi = types.ModuleType("gi")
    gi.require_version = _require_version  # type: ignore[attr-defined]
    repository = types.ModuleType("gi.repository")
    repository.Nautilus = _FakeNautilus
    repository.Gio = _FakeGio
    repository.GObject = _FakeGObject
    gi.repository = repository  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "gi", gi)
    monkeypatch.setitem(sys.modules, "gi.repository", repository)


@pytest.fixture(autouse=True)
def _fresh_bindings() -> None:
    """Each test starts with the fakes empty, whatever the previous one did."""
    _AVAILABLE.clear()
    _AVAILABLE.add("4.1")
    _REQUESTED.clear()
    _FakeGio.DesktopAppInfo.new_calls = []
    _FakeGio.DesktopAppInfo.result = _FakeDesktopAppInfo()
    _FakeDesktopAppInfo.launched = []


@pytest.fixture
def extension(monkeypatch: pytest.MonkeyPatch) -> Any:
    """The module, imported with the fake bindings in place."""
    _install_fake_bindings(monkeypatch)
    monkeypatch.delitem(sys.modules, "berigna_nautilus", raising=False)
    return importlib.import_module("berigna_nautilus")


def _items(extension: Any, files: list[_FakeFile]) -> list[_FakeMenuItem]:
    return extension.BerignaMenuProvider().get_file_items(files)


def _activate(item: _FakeMenuItem) -> None:
    """Fire the signal as Nautilus does: the menu item goes first, then the user data."""
    for _signal, callback, args in item.connected:
        callback(item, *args)


def test_launch_opens_berigna_with_the_selection(extension: Any) -> None:
    files = [_FakeFile("file:///home/prueba/a.pdf"), _FakeFile("file:///home/prueba/b.pdf")]
    assert extension._launch(None, files) is True
    assert _FakeGio.DesktopAppInfo.new_calls == [extension.APP_INFO_ID]
    assert _FakeDesktopAppInfo.launched == [
        ["file:///home/prueba/a.pdf", "file:///home/prueba/b.pdf"]
    ]


def test_launch_without_a_desktop_entry(extension: Any) -> None:
    _FakeGio.DesktopAppInfo.result = None
    assert extension._launch(None, [_FakeFile()]) is False
    assert _FakeDesktopAppInfo.launched == []


def test_only_local_files_count(extension: Any) -> None:
    assert extension._is_local(_FakeFile()) is True
    assert extension._is_local(_FakeFile(scheme="sftp")) is False


def test_menu_for_a_single_file(extension: Any) -> None:
    files = [_FakeFile("file:///home/prueba/acta.pdf")]
    items = _items(extension, files)
    assert [item.kwargs["name"] for item in items] == [
        "BerignaMenuProvider::firmar",
        "BerignaMenuProvider::verificar",
    ]
    assert [item.kwargs["label"] for item in items] == ["Firmar con berigna", "Verificar firma"]
    assert [item.kwargs["tip"] for item in items] == ["Firmar con berigna", "Verificar firma"]
    assert all(item.kwargs["icon"] == extension.ICON for item in items)
    assert all(item.connected == [("activate", extension._launch, (files,))] for item in items)
    _activate(items[0])
    _activate(items[1])
    assert _FakeDesktopAppInfo.launched == [
        ["file:///home/prueba/acta.pdf"],
        ["file:///home/prueba/acta.pdf"],
    ]


def test_menu_for_several_files_offers_only_the_batch(extension: Any) -> None:
    files = [_FakeFile("file:///home/prueba/a.pdf"), _FakeFile("file:///home/prueba/b.pdf")]
    items = _items(extension, files)
    assert [item.kwargs["name"] for item in items] == ["BerignaMenuProvider::firmar"]
    assert items[0].connected == [("activate", extension._launch, (files,))]
    _activate(items[0])
    assert _FakeDesktopAppInfo.launched == [
        ["file:///home/prueba/a.pdf", "file:///home/prueba/b.pdf"]
    ]


def test_menu_for_a_folder_offers_only_the_batch(extension: Any) -> None:
    files = [_FakeFile("file:///home/prueba/carpeta", directory=True)]
    items = _items(extension, files)
    assert [item.kwargs["name"] for item in items] == ["BerignaMenuProvider::firmar"]
    _activate(items[0])
    assert _FakeDesktopAppInfo.launched == [["file:///home/prueba/carpeta"]]


def test_no_items_without_local_files(extension: Any) -> None:
    files = [_FakeFile(scheme="sftp"), _FakeFile(scheme="dav")]
    assert _items(extension, files) == []


@pytest.mark.parametrize(
    ("available", "requested"),
    [({"4.1"}, ["4.1"]), ({"4.0"}, ["4.1", "4.0"])],
    ids=["nautilus-50", "nautilus-48"],
)
def test_the_nautilus_api_of_each_distribution_is_used(
    monkeypatch: pytest.MonkeyPatch, available: set[str], requested: list[str]
) -> None:
    """4.1 in Ubuntu 26.04 (Nautilus 50), 4.0 in Debian 13 (Nautilus 48): asking only for 4.0
    left the menu out of Ubuntu (2026-11-08, ADR-0023)."""
    _AVAILABLE.clear()
    _AVAILABLE.update(available)
    _install_fake_bindings(monkeypatch)
    monkeypatch.delitem(sys.modules, "berigna_nautilus", raising=False)
    importlib.import_module("berigna_nautilus")
    assert _REQUESTED == requested
