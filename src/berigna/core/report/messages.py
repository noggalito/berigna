# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Source strings of the verification explanations and of the error codes (RF-053, PR-I18N-07).

Strings are written in English and marked with ``N_`` for xgettext; they are translated when
shown (:mod:`berigna.core.report.explanations`). The es_PE text is the legally binding one
(ADR-0011 §3). Every ETSI EN 319 102-1 indication and subindication and every ``ERR-xxx`` code
must have an entry here and a translation in ``po/es_PE.po``; the tests enforce both.
"""

from berigna.core.validation import Indication, Modifications


def N_(message: str) -> str:
    return message


INDICATIONS: dict[Indication, str] = {
    Indication.TOTAL_PASSED: N_("The signature is valid."),
    Indication.TOTAL_FAILED: N_("The signature is not valid."),
    Indication.INDETERMINATE: N_("It could not be determined whether the signature is valid."),
}

# Keyed by "INDICATION:SUBINDICATION": NOT_YET_VALID means different things under each.
SUBINDICATIONS: dict[str, str] = {
    "TOTAL_FAILED:FORMAT_FAILURE": N_(
        "The signature is damaged or does not have the expected format."
    ),
    "TOTAL_FAILED:HASH_FAILURE": N_("The signed content was changed after it was signed."),
    "TOTAL_FAILED:SIG_CRYPTO_FAILURE": N_(
        "The signature value does not match the signer's certificate."
    ),
    "TOTAL_FAILED:REVOKED": N_(
        "The signer's certificate had been revoked before the signature was made."
    ),
    "TOTAL_FAILED:NOT_YET_VALID": N_(
        "The signature was made before the signer's certificate became valid."
    ),
    "INDETERMINATE:SIG_CONSTRAINTS_FAILURE": N_(
        "The signature does not meet the requirements of the validation policy."
    ),
    "INDETERMINATE:CHAIN_CONSTRAINTS_FAILURE": N_(
        "A certificate in the chain does not meet the requirements of the validation policy."
    ),
    "INDETERMINATE:CERTIFICATE_CHAIN_GENERAL_FAILURE": N_(
        "The certificate chain of the signer could not be validated."
    ),
    "INDETERMINATE:CRYPTO_CONSTRAINTS_FAILURE": N_(
        "The signature uses an algorithm or a key size that is no longer considered secure."
    ),
    "INDETERMINATE:EXPIRED": N_(
        "The signer's certificate has expired, and nothing proves that the signature was "
        "made while it was valid."
    ),
    "INDETERMINATE:NOT_YET_VALID": N_(
        "The signer's certificate is not yet valid at the time of the verification."
    ),
    "INDETERMINATE:POLICY_PROCESSING_ERROR": N_("The signature policy could not be processed."),
    "INDETERMINATE:SIGNATURE_POLICY_NOT_AVAILABLE": N_(
        "The signature policy that the signature refers to is not available."
    ),
    "INDETERMINATE:TIMESTAMP_ORDER_FAILURE": N_(
        "The time-stamps of the signature are not in a consistent order."
    ),
    "INDETERMINATE:NO_SIGNING_CERTIFICATE_FOUND": N_("The signer's certificate was not found."),
    "INDETERMINATE:NO_CERTIFICATE_CHAIN_FOUND": N_(
        "The signer's certificate does not lead to any trusted root certificate."
    ),
    "INDETERMINATE:REVOKED_NO_POE": N_(
        "The signer's certificate has been revoked, and nothing proves that the signature "
        "was made before the revocation."
    ),
    "INDETERMINATE:REVOKED_CA_NO_POE": N_(
        "A certification authority in the chain has been revoked, and nothing proves that "
        "the signature was made before the revocation."
    ),
    "INDETERMINATE:OUT_OF_BOUNDS_NO_POE": N_(
        "A certificate in the chain is outside its validity period, and nothing proves that "
        "the signature was made while it was valid."
    ),
    "INDETERMINATE:REVOCATION_OUT_OF_BOUNDS_NO_POE": N_(
        "The revocation information is outside its validity period, and nothing proves when "
        "it was obtained."
    ),
    "INDETERMINATE:OUT_OF_BOUNDS_NOT_REVOKED": N_(
        "The signer's certificate has expired without being revoked; a time-stamp is needed "
        "to prove when the signature was made."
    ),
    "INDETERMINATE:CRYPTO_CONSTRAINTS_FAILURE_NO_POE": N_(
        "The signature uses an algorithm that is no longer considered secure, and nothing "
        "proves that it was made while the algorithm still was."
    ),
    "INDETERMINATE:NO_POE": N_("Nothing proves that the signature existed at the required time."),
    "INDETERMINATE:TRY_LATER": N_(
        "The revocation status of a certificate could not be checked. Try again later, with "
        "an Internet connection."
    ),
    "INDETERMINATE:SIGNED_DATA_NOT_FOUND": N_("The signed data was not found."),
    "INDETERMINATE:GENERIC": N_("The signature could not be validated for another reason."),
}

MODIFICATIONS: dict[Modifications, str] = {
    Modifications.NONE: N_("The document has not been changed since it was signed."),
    Modifications.LTA_UPDATES: N_(
        "After signing, only validation data and time-stamps were added; the content has not "
        "changed."
    ),
    Modifications.FORM_FILLING: N_(
        "After signing, form fields were filled in or other signatures were added."
    ),
    Modifications.ANNOTATIONS: N_("After signing, comments or annotations were added."),
    Modifications.OTHER: N_(
        "The document was changed after it was signed. Open the signed version to see exactly "
        "what was signed."
    ),
}

SIGNED_BY = N_("Signed by {name}.")
TIME_CERTIFIED = N_("The time of signing, {time}, is certified by a time-stamping authority.")
TIME_CLAIMED = N_(
    "The time of signing, {time}, was declared by the signer's computer and is not certified."
)
DOCUMENT_TIMESTAMP = N_("Document time-stamp issued on {time}.")
USER_ANCHOR = N_(
    "The chain ends in a root certificate that you added yourself, not in an official one."
)

# Labels of the PDF report (RF-054).
REPORT_TITLE = N_("Signature verification report")
REPORT_FILE = N_("File")
REPORT_SHA256 = N_("SHA-256 of the file")
REPORT_VERIFIED_AT = N_("Verified on")
REPORT_TRUST = N_("Trusted root certificates")
REPORT_TRUST_OFFICIAL = N_("{count} certificates of the official PKI (IOFE)")
REPORT_TRUST_USER = N_("{count} certificates, including roots you added yourself")
REPORT_SIGNATURE = N_("Signature {number} of {total}: {field}")
REPORT_RESULT = N_("Result")
REPORT_ETSI = N_("ETSI EN 319 102-1 code")
REPORT_SIGNER = N_("Signer")
REPORT_ISSUER = N_("Issued by")
REPORT_CLAIMED_TIME = N_("Time declared by the signer")
REPORT_TIMESTAMP = N_("Signature time-stamp")
REPORT_CHANGES = N_("Changes after signing")
REPORT_SIGNED_REVISION = N_("Signed version")
REPORT_SIGNED_BYTES = N_("First {length} bytes of the file")
REPORT_NONE = N_("None")
# A moment, as decided on 2026-10-28: "2026-10-28 a las 18h47 UTC-5".
MOMENT = N_("{date} at {hour}h{minute} {zone}")
REPORT_DOCUMENT_TIMESTAMPS = N_("Document time-stamps")
REPORT_NO_SIGNATURES = N_("This document has no signatures.")
REPORT_GENERATED = N_("Report generated by berigna {version}.")
REPORT_SPANISH_PREVAILS = N_(
    "This report is a translation. In case of discrepancy, the Spanish (es_PE) version prevails."
)
REPORT_PAGE = N_("Page {page}")
# Shown in Quechua and in Spanish while no speaker has reviewed the translation (DP-14,
# BRG-UX-001 §4.2): in the window and in the Quechua PDF report.
UNREVIEWED_TRANSLATION = N_(
    "Translation not reviewed by speakers. If in doubt, the Spanish text prevails."
)

ERRORS: dict[str, str] = {
    "ERR-000": N_("Unexpected error."),
    "ERR-100": N_("Problem with the card reader or the card."),
    "ERR-101": N_("Insert your DNIe in the card reader."),
    "ERR-102": N_("This card is not supported. Only the DNIe is supported."),
    "ERR-103": N_("The DNIe gave an unexpected answer. Remove it and insert it again."),
    "ERR-104": N_("The certificate on the card is not meant for signing."),
    "ERR-105": N_("The DNIe was removed during the operation. Nothing was signed."),
    "ERR-106": N_("Another program is using the DNIe. Close it and try again."),
    "ERR-107": N_("The smart card service (pcscd) is not running. Install it or start it."),
    "ERR-108": N_("Communication with the card failed for a moment. Try again."),
    "ERR-110": N_(
        "The PIN is incorrect. Check it carefully before trying again: after several failed "
        "attempts the DNIe is blocked."
    ),
    # Channels confirmed by RENIEC on 2026-10-28 (CE-07).
    "ERR-111": N_(
        "The PIN is blocked. Unblock it on RENIEC's Ciudadano Digital platform or at a RENIEC "
        "office."
    ),
    "ERR-112": N_("The DNIe did not accept the operation because the PIN was not verified."),
    "ERR-120": N_("berigna refused to send a command that is not allowed to the card."),
    "ERR-200": N_("Problem with the trusted root certificates."),
    "ERR-201": N_(
        "The trusted root certificates installed with berigna have been altered. Reinstall berigna."
    ),
    "ERR-202": N_("A root certificate you added is not valid as a root."),
    "ERR-203": N_(
        "The INDECOPI trusted list could not be used: its signature or its content is not "
        "valid. The trusted root certificates installed with berigna are still used."
    ),
    "ERR-204": N_(
        "The INDECOPI trusted list is out of date. The trusted root certificates installed "
        "with berigna are still used."
    ),
    "ERR-210": N_("Your certificate cannot be used to sign."),
    "ERR-211": N_(
        "Your certificate has expired or is not yet valid. DNIe certificates last four years, "
        "even if the DNI is still valid; renew them on RENIEC's Ciudadano Digital platform."
    ),
    "ERR-212": N_("Your certificate has been revoked. Go to RENIEC."),
    "ERR-213": N_("Your certificate does not lead to a trusted root certificate."),
    "ERR-214": N_("Your certificate could not be validated."),
    "ERR-300": N_("The document could not be signed."),
    "ERR-301": N_(
        "The file changed after you opened it. Open it again and check it before signing."
    ),
    "ERR-302": N_("A file with that name already exists. Choose another name."),
    "ERR-303": N_("Signing was cancelled. The PIN was not sent."),
    "ERR-304": N_("This PDF cannot be signed: it is damaged or protected."),
    "ERR-305": N_("The time-stamping authority did not answer. Check the connection or the TSA."),
    "ERR-306": N_("That signature level is not available now. Choose a lower level."),
    "ERR-308": N_(
        "The visible signature cannot be drawn: the box is too small, the page is rotated or "
        "the image cannot be read. Make the box larger, use another page or choose another "
        "image in Preferences."
    ),
    "ERR-309": N_("Not signed: the batch was cancelled before this file."),
    "ERR-307": N_(
        "The author certified this document so that it cannot be changed: "
        "it does not accept more signatures."
    ),
    "ERR-400": N_("The document could not be verified."),
    "ERR-401": N_("The file is not a document that berigna can read, or it is damaged."),
    "ERR-402": N_("The signature cannot be read, or it is not a CAdES signature."),
}

# Batch report (RF-042): columns and results.
BATCH_COLUMNS = (
    N_("File"),
    N_("Folder"),
    N_("Result"),
    N_("Signed file"),
    N_("Level"),
    N_("SHA-256 of the signed file"),
    N_("Code"),
    N_("Explanation"),
)
BATCH_OUTCOMES = {
    "signed": N_("Signed"),
    "failed": N_("Not signed"),
    "skipped": N_("Skipped"),
}

# History (RF-082): columns of the CSV export and kinds of operation.
HISTORY_COLUMNS = (
    N_("Date (UTC)"),
    N_("Operation"),
    N_("File"),
    N_("SHA-256 of the file"),
    N_("Signed file"),
    N_("SHA-256 of the signed file"),
    N_("Level"),
    N_("Signer"),
    N_("Certificate serial number"),
    N_("Result"),
    N_("Detail"),
)
HISTORY_KINDS = {
    "sign": N_("Signature"),
    "batch": N_("Signature in a batch"),
    "verify": N_("Verification"),
}
