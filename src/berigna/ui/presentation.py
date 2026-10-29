# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Texts and icons the window shows, kept apart from GTK so they can be tested headless."""

import gettext
from collections import Counter
from dataclasses import dataclass

from berigna.core.documents import DocumentInfo, DocumentKind
from berigna.core.formats.pades import SignatureLevel
from berigna.core.report import messages
from berigna.core.report.explanations import (
    common_name,
    display_name,
    explain_signature,
    explain_timestamp,
    format_time,
    masked_id,
)
from berigna.core.signing import SignResult
from berigna.core.token.monitor import DeviceState, DeviceStatus
from berigna.core.trust import TrustStore
from berigna.core.trust.cache import TslRefresh
from berigna.core.validation import Indication, PdfVerification, SignerCheck
from berigna.core.validation.pdf import PdfSignatureReport, TimestampReport
from berigna.ui.i18n import N_, _, catalogue, ngettext

# Every icon the window uses; a test checks they exist in the Adwaita theme.
ICONS = (
    "content-loading-symbolic",
    "dialog-error-symbolic",
    "dialog-warning-symbolic",
    "document-open-symbolic",
    "document-save-symbolic",
    "object-select-symbolic",
    "view-refresh-symbolic",
    "x-office-document-symbolic",
)


@dataclass(frozen=True)
class StatusView:
    icon: str
    message: str
    ready: bool = False


_DEVICE: dict[DeviceState, tuple[str, str]] = {
    DeviceState.PCSC_UNAVAILABLE: (
        "dialog-warning-symbolic",
        N_("The smart card service (pcscd) is not running"),
    ),
    DeviceState.NO_READER: ("media-removable-symbolic", N_("Connect a card reader")),
    DeviceState.NO_CARD: ("auth-smartcard-symbolic", N_("Insert your DNIe in the reader")),
    DeviceState.UNSUPPORTED_CARD: ("dialog-warning-symbolic", N_("This card is not supported")),
    DeviceState.DNIE_READY: ("object-select-symbolic", N_("DNIe ready")),
}


def device_status(status: DeviceStatus | None) -> StatusView:
    """Status bar contents; ``None`` before the first sample of the monitor."""
    if status is None:
        return StatusView("content-loading-symbolic", _("Looking for card readers…"))
    icon, message = _DEVICE[status.state]
    return StatusView(icon, _(message), ready=status.state is DeviceState.DNIE_READY)


def document_summary(info: DocumentInfo) -> str:
    """One line about an opened document: kind, pages and signatures."""
    if info.kind is DocumentKind.OTHER:
        return _("berigna cannot sign or verify this kind of file yet.")
    pages = info.pages or 0
    text = ngettext("PDF document, {n} page", "PDF document, {n} pages", pages).format(n=pages)
    if not info.signed:
        return _("{document}, not signed").format(document=text)
    signatures = ngettext("{n} signature", "{n} signatures", info.signatures).format(
        n=info.signatures
    )
    return _("{document}, {signatures}").format(document=text, signatures=signatures)


# -- Verification (CU-06, BRG-UX-001 §3.4) -------------------------------------------------------

_INDICATION_ICONS = {
    Indication.TOTAL_PASSED: ("object-select-symbolic", "success"),
    Indication.TOTAL_FAILED: ("dialog-error-symbolic", "error"),
    Indication.INDETERMINATE: ("dialog-warning-symbolic", "warning"),
}


@dataclass(frozen=True)
class Detail:
    label: str
    value: str


@dataclass(frozen=True)
class ResultView:
    """One signature or document time-stamp."""

    title: str
    icon: str
    style: str  # CSS class: success, error or warning
    explanation: str
    details: tuple[Detail, ...]
    signed_revision_length: int | None = None  # signatures only: the version that was signed


@dataclass(frozen=True)
class VerificationView:
    icon: str
    style: str
    summary: str
    signatures: tuple[ResultView, ...]
    timestamps: tuple[ResultView, ...]
    retry: bool  # some result is INDETERMINATE: checking again (online) may change it


def etsi_code(indication: Indication, subindication: str | None) -> str:
    return indication.value + (f" / {subindication}" if subindication else "")


def _timestamp_text(stamp: TimestampReport | None) -> str:
    if stamp is None:
        return _(messages.REPORT_NONE)
    parts = [format_time(stamp.time, _)] if stamp.time is not None else []
    if stamp.tsa is not None:
        parts.append(common_name(stamp.tsa))
    parts.append(etsi_code(stamp.indication, stamp.subindication))
    return " · ".join(parts)


def _signature_view(report: PdfSignatureReport, user_anchor: bool) -> ResultView:
    icon, style = _INDICATION_ICONS[report.indication]
    signer = report.signer
    details = [
        Detail(_(messages.REPORT_ETSI), etsi_code(report.indication, report.subindication)),
        Detail(_("Format"), f"PAdES · {report.subfilter}"),
        Detail(_("Signature field"), report.field_name),
    ]
    if signer is not None:
        details += [
            Detail(_(messages.REPORT_SIGNER), common_name(signer)),
            Detail(_(messages.REPORT_ISSUER), display_name(signer.issuer)),
        ]
    claimed = report.claimed_signing_time
    details += [
        Detail(
            _(messages.REPORT_CLAIMED_TIME),
            format_time(claimed, _) if claimed is not None else _(messages.REPORT_NONE),
        ),
        Detail(_(messages.REPORT_TIMESTAMP), _timestamp_text(report.timestamp)),
        Detail(_(messages.REPORT_CHANGES), _(messages.MODIFICATIONS[report.modifications])),
        Detail(
            _(messages.REPORT_SIGNED_REVISION),
            _(messages.REPORT_SIGNED_BYTES).format(length=report.signed_revision_length),
        ),
    ]
    return ResultView(
        title=common_name(signer) if signer is not None else _("Unknown signer"),
        icon=icon,
        style=style,
        explanation=explain_signature(report, catalogue(), user_anchor=user_anchor) or "",
        details=tuple(details),
        signed_revision_length=report.signed_revision_length,
    )


def _timestamp_view(stamp: TimestampReport) -> ResultView:
    icon, style = _INDICATION_ICONS[stamp.indication]
    details = [Detail(_(messages.REPORT_ETSI), etsi_code(stamp.indication, stamp.subindication))]
    if stamp.tsa is not None:
        details.append(Detail(_("Time-stamping authority"), common_name(stamp.tsa)))
    if stamp.field_name is not None:
        details.append(Detail(_("Signature field"), stamp.field_name))
    return ResultView(
        title=format_time(stamp.time, _) if stamp.time is not None else _("Unreadable time"),
        icon=icon,
        style=style,
        explanation=explain_timestamp(stamp, catalogue()) or "",
        details=tuple(details),
    )


def _summary(verification: PdfVerification) -> str:
    reports = verification.signatures
    if not reports:
        return _(messages.REPORT_NO_SIGNATURES)
    count = Counter(report.indication for report in reports)
    parts = []
    if n := count[Indication.TOTAL_PASSED]:
        parts.append(ngettext("{n} valid signature", "{n} valid signatures", n).format(n=n))
    if n := count[Indication.TOTAL_FAILED]:
        parts.append(
            ngettext("{n} signature is not valid", "{n} signatures are not valid", n).format(n=n)
        )
    if n := count[Indication.INDETERMINATE]:
        parts.append(
            ngettext(
                "{n} signature could not be verified", "{n} signatures could not be verified", n
            ).format(n=n)
        )
    last = max(reports, key=lambda report: report.signed_revision_length)
    if last.document_unchanged_since_signing:
        parts.append(_("The document was not changed after the last signature."))
    else:
        parts.append(_("The document was changed after the last signature."))
    return " · ".join(parts)


def verification_view(verification: PdfVerification, store: TrustStore) -> VerificationView:
    """Everything the result page shows, in the current language (RF-053)."""
    user_anchor = any(entry.user_added for entry in store.entries)
    indications = [r.indication for r in verification.signatures] + [
        t.indication for t in verification.document_timestamps
    ]
    if Indication.TOTAL_FAILED in indications:
        icon, style = _INDICATION_ICONS[Indication.TOTAL_FAILED]
    elif Indication.INDETERMINATE in indications or not verification.signatures:
        icon, style = _INDICATION_ICONS[Indication.INDETERMINATE]
    else:
        icon, style = _INDICATION_ICONS[Indication.TOTAL_PASSED]
    return VerificationView(
        icon=icon,
        style=style,
        summary=_summary(verification),
        signatures=tuple(_signature_view(r, user_anchor) for r in verification.signatures),
        timestamps=tuple(_timestamp_view(t) for t in verification.document_timestamps),
        retry=Indication.INDETERMINATE in indications,
    )


# -- Signing (CU-01, BRG-UX-001 §3.2, §3.3 and §4) -----------------------------------------------

LEVELS: dict[SignatureLevel, tuple[str, str]] = {
    SignatureLevel.B_LT: (
        N_("Long-term validation"),
        N_(
            "Also includes the information needed to verify the signature years from now. "
            "Recommended."
        ),
    ),
    SignatureLevel.B_LTA: (
        N_("Long-term archival"),
        N_(
            "Protects the signature against cryptographic obsolescence. "
            "For documents that must be kept for many years."
        ),
    ),
    SignatureLevel.B_T: (
        N_("With timestamp"),
        N_("A timestamping authority certifies the date and time of the signature."),
    ),
    SignatureLevel.B_B: (
        N_("Basic"),
        N_("Signature without a timestamp. The date is declared by your computer."),
    ),
}
NEEDS_TSA = N_("Needs a timestamping authority, which is not configured yet.")


def level_title(level: SignatureLevel, translations: gettext.NullTranslations | None = None) -> str:
    """ "Long-term validation (B-LT)": plain words first, the code as secondary text."""
    gettext_ = (translations or catalogue()).gettext
    return f"{gettext_(LEVELS[level][0])} ({level.value})"


def pin_summary(
    document: DocumentInfo,
    check: SignerCheck,
    level: SignatureLevel,
    translations: gettext.NullTranslations | None = None,
) -> tuple[Detail, ...]:
    """What the PIN dialog shows before the PIN is sent (P-01, BRG-UX-001 §3.3).

    ``translations`` gives it in another language: Quechua users can read it in Spanish.
    """
    t = translations or catalogue()
    certificate = check.chain[-1]
    pages = document.pages or 0
    rows = [
        Detail(
            t.gettext("Document"),
            t.ngettext("{name} ({n} page)", "{name} ({n} pages)", pages).format(
                name=document.path.name, n=pages
            ),
        ),
        Detail(t.gettext(messages.REPORT_SIGNER), common_name(certificate)),
    ]
    identity = masked_id(certificate)
    if identity is not None:
        rows.append(Detail(t.gettext("DNI"), identity))
    rows.append(Detail(t.gettext("Level"), level_title(level, t)))
    return tuple(rows)


def pin_warnings(check: SignerCheck, remaining_tries: int | None) -> tuple[str, ...]:
    """Warnings shown above the PIN entry (P-07, RF-006)."""
    warnings = []
    if remaining_tries is not None:
        warnings.append(
            ngettext(
                "The PIN was not correct. You have {n} try left before the PIN is blocked.",
                "The PIN was not correct. You have {n} tries left before the PIN is blocked.",
                remaining_tries,
            ).format(n=remaining_tries)
        )
    if check.only_basic_level:
        warnings.append(
            _(
                "Revocation of your certificate could not be checked online, "
                "so only a basic signature is possible."
            )
        )
    if check.expires_soon:
        days = max(0, (check.expires - check.moment).days)
        warnings.append(
            ngettext(
                "Your signing certificate expires on {date}, in {n} day. Renew it on RENIEC's "
                "Ciudadano Digital platform to keep signing.",
                "Your signing certificate expires on {date}, in {n} days. Renew it on RENIEC's "
                "Ciudadano Digital platform to keep signing.",
                days,
            ).format(date=check.expires.astimezone().strftime("%Y-%m-%d"), n=days)
        )
    return tuple(warnings)


def signed_summary(result: SignResult, requested: SignatureLevel) -> str:
    """One line under "Document signed": file, level reached and, if it is lower than
    ``requested``, what was left out (the core's note is technical and goes to the log)."""
    text = _("Saved as {name}, level {level}.").format(
        name=result.output.name, level=level_title(result.level)
    )
    if result.level is requested:
        return text
    if result.level is SignatureLevel.B_T:
        missing = _(
            "The validation data could not be added because the revocation services did not answer."
        )
    else:
        missing = _("The document time-stamp could not be added.")
    return f"{text} {missing}"


# -- Preferences (CU-08) ---------------------------------------------------------------------------


def tsl_status(result: TslRefresh | None) -> tuple[str, str]:
    """Title and subtitle of the trusted list row (ADR-0014)."""
    if result is None:
        return _("Checking the trusted list…"), ""
    trusted = result.trusted_list
    if trusted is None:
        return (
            _("Not available"),
            _("Only the root certificates included in berigna are used."),
        )
    authorities = len(trusted.ca_certificates())
    return (
        _("List {sequence}, issued on {date}").format(
            sequence=trusted.sequence_number, date=trusted.issued.strftime("%Y-%m-%d")
        ),
        ngettext(
            "Valid until {date}. {n} accredited certification authority.",
            "Valid until {date}. {n} accredited certification authorities.",
            authorities,
        ).format(date=trusted.next_update.strftime("%Y-%m-%d"), n=authorities),
    )
