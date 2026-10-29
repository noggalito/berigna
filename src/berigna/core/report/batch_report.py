# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Report of a signing batch, one row per file, in CSV (RF-042).

The columns and the explanations go in the requested language; an explanation still waiting
for the Quechua translators is given in Spanish, which prevails (ADR-0015). The report names
the files and their folders, as the user chose them, and nothing about the signer.
"""

import csv
import io
from collections.abc import Sequence

from berigna.core.batch import BatchItem
from berigna.core.i18n import Language, translations
from berigna.core.report import messages
from berigna.core.report.explanations import explain_error


def batch_csv(items: Sequence[BatchItem], language: Language = Language.ES_PE) -> str:
    t = translations(language).gettext
    spanish = translations(Language.ES_PE)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow([t(column) for column in messages.BATCH_COLUMNS])
    for item in items:
        result = item.result
        explanation = ""
        if item.code is not None:
            explanation = (
                explain_error(item.code, translations(language))
                or explain_error(item.code, spanish)
                or ""
            )
        writer.writerow(
            [
                item.job.source.name,
                str(item.job.source.parent),
                t(messages.BATCH_OUTCOMES[item.outcome.value]),
                result.output.name if result else "",
                result.level.value if result else "",
                result.sha256 if result else "",
                item.code or "",
                explanation,
            ]
        )
    return out.getvalue()
