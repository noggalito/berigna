# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Reasons for signing in a list, plus "Other" (decision of 2026-10-28)."""

from berigna.core.i18n import NAME, Language
from berigna.core.reasons import TEXTS, Reason, reason_text


def test_reasons_are_written_in_the_language_of_the_signature() -> None:
    assert reason_text(Reason.AGREEMENT, "", Language.ES_PE) == "En señal de conformidad"
    assert reason_text(Reason.AUTHORSHIP, "", Language.QUZ_PE) == "Qillqaq kamachiqnin"
    assert reason_text(Reason.NONE, "ignored", Language.ES_PE) is None
    assert reason_text(Reason.OTHER, "  Por encargo ", Language.ES_PE) == "Por encargo"
    assert reason_text(Reason.OTHER, "  ", Language.ES_PE) is None
    assert set(TEXTS) == set(Reason) - {Reason.NONE, Reason.OTHER}


def test_the_name_as_a_word() -> None:
    found = [m.start() for m in NAME.finditer("berigna: berigna-prueba.pdf, ~/berigna y berigna.")]
    assert found == [0, 41]
    # Quechua suffixes: the name is still found, and only the name is matched.
    assert [m.group() for m in NAME.finditer("berignaqa, berignawan; berigna-ruwasqakuna.csv")] == [
        "berigna",
        "berigna",
    ]


def test_pending_quechua_reason_falls_back_to_spanish(pending_quechua: None) -> None:
    assert reason_text(Reason.AUTHORSHIP, "", Language.QUZ_PE) == "Autoría del documento"
