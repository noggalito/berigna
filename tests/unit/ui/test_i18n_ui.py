# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
import os
from collections.abc import Iterator

import pytest

from berigna.core.i18n import Language
from berigna.ui import i18n


@pytest.fixture(autouse=True)
def spanish(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv("LANGUAGE", raising=False)
    yield
    i18n.set_language(Language.ES_PE)


@pytest.mark.parametrize(
    ("setting", "environ", "language"),
    [
        ("system", {"LANG": "quz_PE.UTF-8"}, Language.QUZ_PE),
        ("system", {"LANG": "en_US.UTF-8"}, Language.ES_PE),
        ("system", {}, Language.ES_PE),
        ("es_PE", {"LANG": "quz_PE.UTF-8"}, Language.ES_PE),
        ("quz_PE", {"LANG": "es_PE.UTF-8"}, Language.QUZ_PE),
    ],
)
def test_choose_language(setting: str, environ: dict[str, str], language: Language) -> None:
    assert i18n.choose_language(setting, environ) is language


def test_set_language_also_steers_gtk() -> None:
    i18n.set_language(Language.QUZ_PE)
    assert i18n.current_language() is Language.QUZ_PE
    assert os.environ["LANGUAGE"] == "quz:es_PE"
    i18n.set_language(Language.ES_PE)
    assert os.environ["LANGUAGE"] == "es_PE"


def test_quechua_pending_strings_fall_back_to_spanish() -> None:
    i18n.set_language(Language.QUZ_PE)
    assert i18n._("DNIe ready") == "DNIe listo"
    assert i18n.ngettext("{n} signature", "{n} signatures", 2) == "{n} firmas"


def test_translate_view() -> None:
    view = b"""<interface>
      <object class="GtkLabel">
        <property name="label" translatable="yes" comments="for translators">DNIe ready</property>
        <property name="tooltip-text" translatable="yes" context="unknown">DNIe ready</property>
        <property name="name">DNIe ready</property>
      </object>
    </interface>"""
    out = i18n.translate_view(view)
    assert out.count("DNIe listo") == 1
    # A context the catalogue lacks gives the source back, as gettext does; the catalogue
    # tests make sure every string of the views is translated.
    assert out.count(">DNIe ready<") == 2
    for attribute in ("translatable", "comments", "context"):
        assert attribute not in out


def test_translate_view_ignores_entities() -> None:
    view = b"""<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>
    <interface><object class="GtkLabel">
      <property name="label">&e;</property>
    </object></interface>"""
    assert "root:" not in i18n.translate_view(view)
