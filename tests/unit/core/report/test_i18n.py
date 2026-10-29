# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Languages of berigna 1.0 (ADR-0015): choice, fallbacks and catalogues (PR-I18N-04)."""

import gettext
from pathlib import Path

import pytest

from berigna.core.i18n import (
    DOMAIN,
    Language,
    localedir,
    resolve_language,
    system_preferences,
    translations,
)


@pytest.mark.parametrize(
    ("preferences", "language"),
    [
        (["quz_PE.UTF-8"], Language.QUZ_PE),
        (["quy_PE"], Language.QUZ_PE),
        (["qu"], Language.QUZ_PE),
        (["es_MX"], Language.ES_PE),
        (["es_ES@euro"], Language.ES_PE),
        (["fr_FR"], Language.ES_PE),
        (["en_US"], Language.ES_PE),
        (["C"], Language.ES_PE),
        (["en_US", "quz_PE"], Language.QUZ_PE),  # first preference berigna offers
        ([], Language.ES_PE),
    ],
)
def test_language_choice_and_fallback(preferences: list[str], language: Language) -> None:
    assert resolve_language(preferences) is language


def test_preferences_follow_gettext_order() -> None:
    env = {"LANG": "es_PE.UTF-8", "LC_MESSAGES": "fr_FR", "LANGUAGE": "quz_PE:es_PE"}
    assert system_preferences(env) == ["quz_PE", "es_PE"]
    assert system_preferences({"LANG": "es_PE.UTF-8"}) == ["es_PE.UTF-8"]
    assert system_preferences({}) == []


def test_preferences_default_to_the_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LANGUAGE", "LC_ALL", "LC_MESSAGES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LANG", "quy_PE")
    assert system_preferences() == ["quy_PE"]


def test_catalogues_are_compiled() -> None:
    assert localedir() is not None, "set BERIGNA_LOCALEDIR (scripts/traducciones.sh compilar)"
    for name in ("es_PE", "quz", "quy", "qu"):
        assert gettext.find(DOMAIN, localedir(), [name]) is not None, name


def test_spanish_catalogue_translates() -> None:
    assert translations(Language.ES_PE).gettext("The signature is valid.") == "La firma es válida."


def test_quechua_never_shows_the_english_source() -> None:
    """Strings still waiting for the translators fall back to es_PE (ADR-0015 §5)."""
    catalogue = translations(Language.QUZ_PE)
    assert catalogue.gettext("The signature is valid.") != "The signature is valid."


def test_strict_quechua_never_answers_in_spanish() -> None:
    """Strict mode has no es_PE fallback: a pending string comes back as the source."""
    message = "The signature is valid."
    strict = translations(Language.QUZ_PE, strict=True)
    assert strict.gettext(message) != translations(Language.ES_PE).gettext(message)
    assert Language.QUZ_PE.catalogue == "quz"
    assert Language.ES_PE.catalogue == "es_PE"


def test_missing_catalogues_do_not_break_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An incomplete installation: explanations stay empty, reports are still produced."""
    from berigna.core.report.explanations import explain_error
    from berigna.core.report.json_report import report_data
    from berigna.core.report.pdf_report import pdf_report
    from berigna.core.validation import PdfVerification
    from support.pki import NOW, build_pki

    monkeypatch.setenv("BERIGNA_LOCALEDIR", str(tmp_path))
    for language in Language:
        assert translations(language).gettext("The signature is valid.") == (
            "The signature is valid."
        )
    assert explain_error("ERR-101", translations(Language.ES_PE)) is None
    store = build_pki().store
    empty = PdfVerification((), (), NOW)
    assert report_data(empty, file_name="a.pdf", file_sha256="00", store=store)["signatures"] == []
    assert pdf_report(empty, file_name="a.pdf", file_sha256="00", store=store).startswith(b"%PDF")
