# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
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


class TrustError(BerignaError):
    """Problem with the trust store (ADR-0009)."""

    code = "ERR-200"


class TrustStoreIntegrityError(TrustError):
    """The bundled trust anchors do not match their manifest; the store must not be used."""

    code = "ERR-201"


class InvalidAnchorError(TrustError):
    """A certificate offered as trust anchor is not a CA certificate."""

    code = "ERR-202"


class TslError(TrustError):
    """The INDECOPI trusted list cannot be used (signature, signer, format or rollback)."""

    code = "ERR-203"


class TslExpiredError(TslError):
    """The trusted list is past its NextUpdate date."""

    code = "ERR-204"


class SignerCertificateError(BerignaError):
    """The signer certificate cannot be used to sign now (RF-006). Checked before the PIN."""

    code = "ERR-210"


class CertificateExpiredError(SignerCertificateError):
    """The certificate (or one in its chain) is expired or not yet valid."""

    code = "ERR-211"


class CertificateRevokedError(SignerCertificateError):
    """The certificate (or one in its chain) is revoked."""

    code = "ERR-212"


class UntrustedCertificateError(SignerCertificateError):
    """No chain to a trust anchor of the IOFE could be built (ADR-0009)."""

    code = "ERR-213"


class CertificateValidationError(SignerCertificateError):
    """Any other validation failure (bad signature, disallowed algorithm, wrong usage)."""

    code = "ERR-214"


class SigningError(BerignaError):
    """The document could not be signed."""

    code = "ERR-300"


class SourceChangedError(SigningError):
    """The file on disk changed after it was shown to the user (RF-018, AM-02)."""

    code = "ERR-301"


class OutputExistsError(SigningError):
    """The output file already exists; berigna never overwrites without consent (RF-045)."""

    code = "ERR-302"


class SigningCancelledError(SigningError):
    """The user cancelled before the PIN was sent."""

    code = "ERR-303"


class PdfFormatError(SigningError):
    """The PDF cannot be signed (damaged, encrypted or with forbidden modifications)."""

    code = "ERR-304"


class TsaError(SigningError):
    """The TSA could not be reached or did not issue a valid time-stamp."""

    code = "ERR-305"


class LevelNotAvailableError(SigningError):
    """The requested signature level cannot be produced (no TSA, or revocation not checked)."""

    code = "ERR-306"


class AppearanceError(SigningError):
    """The visible signature cannot be drawn: box too small, or an image that cannot be read."""

    code = "ERR-308"


class CertifiedDocumentError(PdfFormatError):
    """The author certified the document so that no change, not even a signature, is allowed
    (DocMDP P=1, CU-03)."""

    code = "ERR-307"


class VerificationError(BerignaError):
    """A document could not be verified at all (individual signature results are not errors)."""

    code = "ERR-400"


class UnreadableDocumentError(VerificationError):
    """The file is not a document of the expected format, or it is damaged."""

    code = "ERR-401"
