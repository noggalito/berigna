# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Contextual help (ADR-0017)."""

import pytest
from gi.repository import Gtk

from berigna import __version__
from berigna.core.i18n import Language
from berigna.ui import help as help_module
from berigna.ui import i18n
from berigna.ui.help import HelpTopic, help_button, help_url


def test_help_url_follows_the_version_and_the_language() -> None:
    version = ".".join(__version__.split(".")[:2])
    assert help_url(HelpTopic.SIGNATURE_LEVELS) == (
        f"https://berigna.noggalito.com/ayuda/{version}/es/niveles-de-firma"
    )
    try:
        i18n.set_language(Language.QUZ_PE)
        assert "/quz/" in help_url(HelpTopic.PROXY)
    finally:
        i18n.set_language(Language.ES_PE)


def test_help_button_opens_the_page(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []

    class FakeLauncher:
        def __init__(self, uri: str) -> None:
            self.uri = uri

        def launch(self, *_args: object) -> None:
            opened.append(self.uri)

    monkeypatch.setattr(help_module.Gtk, "UriLauncher", FakeLauncher)
    button = help_button(HelpTopic.TRUSTED_LIST)
    assert button.get_tooltip_text() == "Más información"
    button.emit("clicked")
    assert opened == [help_url(HelpTopic.TRUSTED_LIST)]
    assert isinstance(button, Gtk.Button)
