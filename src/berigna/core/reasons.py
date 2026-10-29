# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Reasons for signing offered in a list, plus "Other" (decision of 2026-10-28).

The reason goes in the signature dictionary (/Reason) and in the visible stamp, and validators
such as ReFirma show it: it states why the signer signs. The usual reasons are worded as nouns,
which read the same for any signer, and are written in the language of the signature (RF-092),
not in that of the interface.
"""

import enum

from berigna.core.i18n import Language, translations


def N_(message: str) -> str:
    return message


class Reason(enum.Enum):
    NONE = "none"
    AUTHORSHIP = "authorship"
    AGREEMENT = "agreement"
    ENDORSEMENT = "endorsement"
    APPROVAL = "approval"
    ON_BEHALF = "on-behalf"
    OTHER = "other"


TEXTS = {
    Reason.AUTHORSHIP: N_("Authorship of the document"),
    Reason.AGREEMENT: N_("In agreement"),
    Reason.ENDORSEMENT: N_("Endorsement (V° B°)"),
    Reason.APPROVAL: N_("Approval of the document"),
    # Signing for someone else who asked for it, as ReFirma offers it ("Por encargo").
    Reason.ON_BEHALF: N_("On behalf of another person"),
}


def reason_text(reason: Reason, other: str, language: Language) -> str | None:
    """The text written in the signature; ``other`` is what the user typed for OTHER."""
    if reason is Reason.OTHER:
        return other.strip() or None
    message = TEXTS.get(reason)
    return translations(language).gettext(message) if message else None
