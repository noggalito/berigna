# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Error hierarchy of the core.

Every error carries a stable ``code`` (ERR-xxx) that the UI maps to a translated message
(docs/06-ux, error catalogue). Messages here are for logs and developers, in English.
"""


class BerignaError(Exception):
    """Base class for all berigna errors."""

    code = "ERR-000"


class TokenError(BerignaError):
    """Problem with the reader, the card or the token backend."""

    code = "ERR-100"


class CardNotFoundError(TokenError):
    """No reader contains a supported card."""

    code = "ERR-101"


class UnsupportedCardError(TokenError):
    """The card is present but no backend supports it."""

    code = "ERR-102"


class CardCommunicationError(TokenError):
    """The card answered with an unexpected status word."""

    code = "ERR-103"

    def __init__(self, message: str, status_word: int | None = None) -> None:
        super().__init__(message)
        self.status_word = status_word


class CardTransientError(CardCommunicationError):
    """A PC/SC exchange failed transiently (SCARD_E_NOT_TRANSACTED); the session stays open.

    Seen in about 3 % of back-to-back sessions right after the previous one powered the card
    off. Only idempotent commands may be retried (SELECT, READ BINARY); never VERIFY or PSO.
    """

    code = "ERR-108"


class CardRemovedError(TokenError):
    """The card was removed or the reader disconnected during an operation (PR-SEG-04)."""

    code = "ERR-105"


class CardInUseError(TokenError):
    """Another program holds the card; berigna needs it exclusively (AM-01)."""

    code = "ERR-106"


class PcscUnavailableError(TokenError):
    """The PC/SC service (pcscd) is not reachable (RF-001)."""

    code = "ERR-107"


class CertificateUsageError(TokenError):
    """The certificate does not have the key usage required for the operation (RF-004)."""

    code = "ERR-104"


class PinIncorrectError(TokenError):
    """The card rejected the PIN. ``remaining_tries`` is None when the card did not say."""

    code = "ERR-110"

    def __init__(self, remaining_tries: int | None) -> None:
        super().__init__(f"PIN rejected; remaining tries: {remaining_tries}")
        self.remaining_tries = remaining_tries


class PinBlockedError(TokenError):
    """The PIN is blocked; it must be unblocked through RENIEC."""

    code = "ERR-111"


class NotAuthenticatedError(TokenError):
    """A private-key operation was attempted without a verified PIN."""

    code = "ERR-112"


class InstructionNotAllowedError(TokenError):
    """The driver refused to send an instruction outside its allow-list (ADR-0012)."""

    code = "ERR-120"
