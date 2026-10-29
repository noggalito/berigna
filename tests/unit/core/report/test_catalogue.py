# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Every result and every error has its text, translated into es_PE (RF-053, PR-I18N-07)."""

import ast
import inspect
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from pyhanko.sign.ades.report import AdESFailure, AdESIndeterminate

from berigna.core import errors
from berigna.core.i18n import Language, translations
from berigna.core.report import messages
from berigna.core.validation import Indication, Modifications

REPOSITORY = Path(__file__).resolve().parents[4]


def _all_messages() -> list[str]:
    singles = [
        messages.SIGNED_BY,
        messages.TIME_CERTIFIED,
        messages.TIME_CLAIMED,
        messages.DOCUMENT_TIMESTAMP,
        messages.USER_ANCHOR,
    ]
    return [
        *messages.INDICATIONS.values(),
        *messages.SUBINDICATIONS.values(),
        *messages.MODIFICATIONS.values(),
        *messages.ERRORS.values(),
        *singles,
    ]


def test_every_etsi_subindication_has_an_explanation() -> None:
    expected = {f"TOTAL_FAILED:{m.name}" for m in AdESFailure} | {
        f"INDETERMINATE:{m.name}" for m in AdESIndeterminate
    }
    assert expected <= set(messages.SUBINDICATIONS)


def test_every_indication_and_modification_has_a_text() -> None:
    assert set(messages.INDICATIONS) == set(Indication)
    assert set(messages.MODIFICATIONS) == set(Modifications)


def test_every_error_code_has_a_message() -> None:
    codes = {
        cls.code
        for _, cls in inspect.getmembers(errors, inspect.isclass)
        if issubclass(cls, errors.BerignaError)
    }
    assert codes == set(messages.ERRORS)


def test_spanish_catalogue_is_complete() -> None:
    catalogue = translations(Language.ES_PE)
    missing = [m for m in _all_messages() if catalogue.gettext(m) == m]
    assert missing == []


@pytest.mark.parametrize("catalogue", ["es_PE", "quz"])
def test_po_has_no_pending_entries(catalogue: str) -> None:
    """Every entry of the template, the interface included, is translated into es_PE and into
    Quechua (RF-090, RNF-USA-07, ADR-0015): a new string comes with both translations."""
    if shutil.which("msgfmt") is None:
        pytest.fail("GNU gettext is needed: apt install gettext")
    result = subprocess.run(  # noqa: S603 - fixed program, catalogue from the parameters
        ["msgfmt", "--statistics", "--output-file=/dev/null", f"po/{catalogue}.po"],  # noqa: S607
        cwd=REPOSITORY,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    assert "untranslated" not in result.stderr
    assert "fuzzy" not in result.stderr


def test_placeholders_survive_translation() -> None:
    catalogue = translations(Language.ES_PE)
    for message in _all_messages():
        assert re.findall(r"{\w+}", catalogue.gettext(message)) == re.findall(r"{\w+}", message)


def test_template_is_up_to_date(tmp_path: Path) -> None:
    """po/berigna.pot must list exactly the marked strings (scripts/traducciones.sh actualizar)."""
    if shutil.which("xgettext") is None:
        pytest.fail("GNU gettext is needed: apt install gettext")
    fresh = tmp_path / "fresh.pot"
    sources = [
        line
        for line in (REPOSITORY / "po" / "POTFILES").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    python = [s for s in sources if s.endswith(".py")]
    views = [s for s in sources if s.endswith(".blp")]
    desktop = [s for s in sources if s.endswith(".desktop.in")]
    for language, keywords, files, extra in (
        ("Python", ["--keyword=N_", "--keyword=_"], python, []),
        ("C", ["--keyword=_", "--keyword=C_:1c,2"], views, ["--join-existing"]),
        ("Desktop", [], desktop, ["--join-existing"]),
    ):
        subprocess.run(  # noqa: S603 - fixed arguments
            [  # noqa: S607 - the system's xgettext
                "xgettext",
                f"--language={language}",
                "--from-code=UTF-8",
                *keywords,
                *extra,
                f"--output={fresh}",
                *files,
            ],
            cwd=REPOSITORY,
            check=True,
        )

    def msgids(path: Path) -> set[str]:
        found, current, inside = set(), "", False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("msgid "):
                current, inside = ast.literal_eval(line[6:]), True
            elif inside and line.startswith('"'):
                current += ast.literal_eval(line)
            elif inside:
                found.add(current)
                inside = False
        return found - {""}

    assert msgids(fresh) == msgids(REPOSITORY / "po" / "berigna.pot")
