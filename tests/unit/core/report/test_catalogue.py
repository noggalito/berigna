# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
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


def test_placeholders_survive_translation() -> None:
    catalogue = translations(Language.ES_PE)
    for message in _all_messages():
        assert re.findall(r"{\w+}", catalogue.gettext(message)) == re.findall(r"{\w+}", message)


def test_template_is_up_to_date(tmp_path: Path) -> None:
    """po/berigna.pot must list exactly the marked strings (scripts/traducciones.sh actualizar)."""
    if shutil.which("xgettext") is None:
        pytest.fail("GNU gettext is needed: apt install gettext")
    fresh = tmp_path / "fresh.pot"
    subprocess.run(  # noqa: S603 - fixed arguments
        [  # noqa: S607 - the system's xgettext
            "xgettext",
            "--language=Python",
            "--from-code=UTF-8",
            "--keyword=N_",
            "--keyword=_",
            f"--output={fresh}",
            "src/berigna/core/report/messages.py",
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
