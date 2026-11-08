# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Texts and icons the window shows, kept apart from GTK so they can be tested headless."""

import datetime as dt
import gettext
from collections import Counter
from dataclasses import dataclass

from berigna.core.diagnostics import Result as DiagnosisResult
from berigna.core.diagnostics import Status as DiagnosisStatus
from berigna.core.diagnostics import Step
from berigna.core.documents import DocumentInfo, DocumentKind
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.pades import SignatureLevel
from berigna.core.formats.xades import XadesPackaging
from berigna.core.report import messages
from berigna.core.report.explanations import (
    common_name,
    display_name,
    explain_error,
    explain_signature,
    explain_timestamp,
    format_time,
    mask_numbers,
    masked_id,
)
from berigna.core.signing import Packaging, SignResult
from berigna.core.token.monitor import DeviceState, DeviceStatus
from berigna.core.trust import TrustStore
from berigna.core.trust.cache import TslRefresh
from berigna.core.trust.store import TrustedCertificate
from berigna.core.validation import (
    Indication,
    PdfVerification,
    SignerCheck,
    XadesSignatureReport,
)
from berigna.core.validation.pdf import PdfSignatureReport, TimestampReport
from berigna.core.verification import SignatureReport, Verification
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
class Detail:
    label: str
    value: str


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
    signatures = ngettext("{n} signature", "{n} signatures", info.signatures).format(
        n=info.signatures
    )
    if info.kind in (DocumentKind.OTHER, DocumentKind.CADES):
        return _("File to sign in CAdES")
    if info.kind is DocumentKind.XML:
        text = _("XML document")
    else:
        pages = info.pages or 0
        text = ngettext("PDF document, {n} page", "PDF document, {n} pages", pages).format(n=pages)
    if not info.signed:
        return _("{document}, not signed").format(document=text)
    return _("{document}, {signatures}").format(document=text, signatures=signatures)


def file_size(size: int, translations: gettext.NullTranslations | None = None) -> str:
    """The size as people read it, and exact: "1,2 MB (1 234 567 bytes)" (CU-05 step 3)."""
    t = translations or catalogue()
    exact = t.ngettext("{n} byte", "{n} bytes", size).format(n=f"{size:,}".replace(",", " "))
    if size < 1000:
        return exact
    for unit, factor in (("GB", 10**9), ("MB", 10**6), ("kB", 10**3)):
        if size >= factor:
            amount = f"{size / factor:.1f}".replace(".", ",")
            return f"{amount} {unit} ({exact})"
    return exact  # pragma: no cover - size >= 1000 always meets the kB factor


def grouped_digest(digest: str) -> str:
    """A hex digest in groups of four, to compare by eye with another program's."""
    return " ".join(digest.upper()[i : i + 4] for i in range(0, len(digest), 4))


def file_details(info: DocumentInfo, type_name: str) -> tuple[Detail, ...]:
    """What the user checks before signing a file that cannot be previewed (WYSIWYS, CU-05
    step 3): name, size, type and SHA-256. ``type_name`` is the description of the desktop
    (shared-mime-info), in the language of the interface."""
    return (
        Detail(_("Name"), info.path.name),
        Detail(_("Size"), file_size(info.size)),
        Detail(_("Type"), type_name),
        Detail("SHA-256", grouped_digest(info.sha256)),
    )


# Packagings of CAdES and XAdES (CU-05 step 2), with what each one writes.
PACKAGING_DESCRIPTIONS: dict[CadesPackaging | XadesPackaging, str] = {
    CadesPackaging.DETACHED: N_(
        "The signature goes in a separate .p7s file and the original does not change. "
        "Whoever verifies it needs both files."
    ),
    CadesPackaging.ENVELOPING: N_("A .p7m file holds the signature and a copy of the file."),
    XadesPackaging.ENVELOPED: N_(
        "The signature goes inside a copy of the XML document. Recommended for XML."
    ),
    XadesPackaging.ENVELOPING: N_("The XML document goes inside the signature."),
    XadesPackaging.DETACHED: N_(
        "The signature goes in a separate .xsig file that names the document, which does "
        "not change. Whoever verifies it needs both files."
    ),
}


# Where a standard packaging and Firma Perú, the official validator, differ (BRG-CAL-006
# §3.10): berigna keeps the standard and says so (decision of the holder, 2026-11-03).
PACKAGING_NOTES: dict[CadesPackaging | XadesPackaging, str] = {
    CadesPackaging.ENVELOPING: N_(
        "Firma Perú does not recognize the .p7m extension: to validate this signature there, "
        "change the extension to .p7s and upload the original file first (berigna can save "
        "it from the .p7m)."
    ),
    XadesPackaging.DETACHED: N_(
        "Firma Perú does not validate .xsig signatures; other validators, such as DSS, do."
    ),
}


def packaging_note(packaging: CadesPackaging | XadesPackaging) -> str | None:
    """The difference with Firma Perú of ``packaging``, if any, in the interface language."""
    note = PACKAGING_NOTES.get(packaging)
    return _(note) if note is not None else None


def packaging_description(packaging: CadesPackaging | XadesPackaging) -> str:
    """What ``packaging`` writes and, if any, how Firma Perú differs (CU-05 step 2)."""
    note = packaging_note(packaging)
    described = _(PACKAGING_DESCRIPTIONS[packaging])
    return f"{described} {note}" if note else described


def packaging_title(
    packaging: CadesPackaging | XadesPackaging, translations: gettext.NullTranslations | None = None
) -> str:
    return (translations or catalogue()).gettext(messages.PACKAGINGS[packaging])


def packagings_for(kind: DocumentKind) -> tuple[CadesPackaging | XadesPackaging, ...]:
    """The packagings a file of ``kind`` can be signed in, the proposed one first (CU-05
    step 2): XAdES enveloped for XML, CAdES detached for the rest."""
    cades = (CadesPackaging.DETACHED, CadesPackaging.ENVELOPING)
    if kind is DocumentKind.XML:
        return (
            XadesPackaging.ENVELOPED,
            XadesPackaging.ENVELOPING,
            XadesPackaging.DETACHED,
            *cades,
        )
    return cades


# -- Verification (CU-06, BRG-UX-001 §3.4) -------------------------------------------------------

_INDICATION_ICONS = {
    Indication.TOTAL_PASSED: ("object-select-symbolic", "success"),
    Indication.TOTAL_FAILED: ("dialog-error-symbolic", "error"),
    Indication.INDETERMINATE: ("dialog-warning-symbolic", "warning"),
}


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


def _timestamp_text(stamp: TimestampReport | None, t: gettext.NullTranslations) -> str:
    if stamp is None:
        return t.gettext(messages.REPORT_NONE)
    parts = [format_time(stamp.time, t.gettext)] if stamp.time is not None else []
    if stamp.tsa is not None:
        parts.append(common_name(stamp.tsa))
    parts.append(etsi_code(stamp.indication, stamp.subindication))
    return " · ".join(parts)


def _format_details(report: SignatureReport, t: gettext.NullTranslations) -> list[Detail]:
    if isinstance(report, PdfSignatureReport):
        return [
            Detail(t.gettext(messages.REPORT_FORMAT), f"PAdES · {report.subfilter}"),
            Detail(t.gettext("Signature field"), report.field_name),
        ]
    return [Detail(t.gettext(messages.REPORT_FORMAT), packaging_title(report.packaging, t))]


def _content_details(report: SignatureReport, t: gettext.NullTranslations) -> list[Detail]:
    """Changes and signed revision of a PDF; what a XAdES covers (AM-06); archive stamps."""
    if isinstance(report, PdfSignatureReport):
        return [
            Detail(
                t.gettext(messages.REPORT_CHANGES),
                t.gettext(messages.MODIFICATIONS[report.modifications]),
            ),
            Detail(
                t.gettext(messages.REPORT_SIGNED_REVISION),
                t.gettext(messages.REPORT_SIGNED_BYTES).format(
                    length=report.signed_revision_length
                ),
            ),
        ]
    details = []
    if isinstance(report, XadesSignatureReport) and report.scope is not None:
        details.append(
            Detail(t.gettext(messages.REPORT_SCOPE), t.gettext(messages.SCOPES[report.scope]))
        )
    details += [
        Detail(t.gettext(messages.REPORT_ARCHIVE_TIMESTAMPS), _timestamp_text(stamp, t))
        for stamp in report.archive_timestamps
    ]
    return details


def _signature_view(
    report: SignatureReport, user_anchor: bool, t: gettext.NullTranslations
) -> ResultView:
    icon, style = _INDICATION_ICONS[report.indication]
    signer = report.signer
    details = [
        Detail(t.gettext(messages.REPORT_ETSI), etsi_code(report.indication, report.subindication)),
        *_format_details(report, t),
    ]
    if signer is not None:
        details += [
            Detail(t.gettext(messages.REPORT_SIGNER), common_name(signer)),
            Detail(t.gettext(messages.REPORT_ISSUER), display_name(signer.issuer)),
        ]
    claimed = report.claimed_signing_time
    details += [
        Detail(
            t.gettext(messages.REPORT_CLAIMED_TIME),
            format_time(claimed, t.gettext)
            if claimed is not None
            else t.gettext(messages.REPORT_NONE),
        ),
        Detail(t.gettext(messages.REPORT_TIMESTAMP), _timestamp_text(report.timestamp, t)),
        *_content_details(report, t),
    ]
    return ResultView(
        title=common_name(signer) if signer is not None else t.gettext("Unknown signer"),
        icon=icon,
        style=style,
        explanation=explain_signature(report, t, user_anchor=user_anchor) or "",
        details=tuple(details),
        signed_revision_length=report.signed_revision_length
        if isinstance(report, PdfSignatureReport)
        else None,
    )


def _timestamp_view(stamp: TimestampReport, t: gettext.NullTranslations) -> ResultView:
    icon, style = _INDICATION_ICONS[stamp.indication]
    details = [
        Detail(t.gettext(messages.REPORT_ETSI), etsi_code(stamp.indication, stamp.subindication))
    ]
    if stamp.tsa is not None:
        details.append(Detail(t.gettext("Time-stamping authority"), common_name(stamp.tsa)))
    if stamp.field_name is not None:
        details.append(Detail(t.gettext("Signature field"), stamp.field_name))
    return ResultView(
        title=format_time(stamp.time, t.gettext)
        if stamp.time is not None
        else t.gettext("Unreadable time"),
        icon=icon,
        style=style,
        explanation=explain_timestamp(stamp, t) or "",
        details=tuple(details),
    )


def _summary(verification: Verification, t: gettext.NullTranslations) -> str:
    reports: tuple[SignatureReport, ...] = verification.signatures
    if not reports:
        return t.gettext(messages.REPORT_NO_SIGNATURES)
    count = Counter(report.indication for report in reports)
    parts = []
    if n := count[Indication.TOTAL_PASSED]:
        parts.append(t.ngettext("{n} valid signature", "{n} valid signatures", n).format(n=n))
    if n := count[Indication.TOTAL_FAILED]:
        parts.append(
            t.ngettext("{n} signature is not valid", "{n} signatures are not valid", n).format(n=n)
        )
    if n := count[Indication.INDETERMINATE]:
        parts.append(
            t.ngettext(
                "{n} signature could not be verified", "{n} signatures could not be verified", n
            ).format(n=n)
        )
    if not isinstance(verification, PdfVerification):  # the digest covers all that was signed
        return " · ".join(parts)
    last = max(verification.signatures, key=lambda report: report.signed_revision_length)
    if last.document_unchanged_since_signing:
        parts.append(t.gettext("The document was not changed after the last signature."))
    else:
        parts.append(t.gettext("The document was changed after the last signature."))
    return " · ".join(parts)


def document_timestamps(verification: Verification) -> tuple[TimestampReport, ...]:
    """The document time-stamps of a PDF; CAdES and XAdES have none."""
    if isinstance(verification, PdfVerification):
        return verification.document_timestamps
    return ()


def verification_view(
    verification: Verification,
    store: TrustStore,
    translations: gettext.NullTranslations | None = None,
) -> VerificationView:
    """Everything the result page shows, in the current language (RF-053).

    ``translations`` gives it in another language: Quechua users can read it in Spanish.
    """
    t = translations or catalogue()
    user_anchor = any(entry.user_added for entry in store.entries)
    reports: tuple[SignatureReport, ...] = verification.signatures
    stamps = document_timestamps(verification)
    indications = [r.indication for r in reports] + [stamp.indication for stamp in stamps]
    if Indication.TOTAL_FAILED in indications:
        icon, style = _INDICATION_ICONS[Indication.TOTAL_FAILED]
    elif Indication.INDETERMINATE in indications or not verification.signatures:
        icon, style = _INDICATION_ICONS[Indication.INDETERMINATE]
    else:
        icon, style = _INDICATION_ICONS[Indication.TOTAL_PASSED]
    return VerificationView(
        icon=icon,
        style=style,
        summary=_summary(verification, t),
        signatures=tuple(_signature_view(r, user_anchor, t) for r in reports),
        timestamps=tuple(_timestamp_view(stamp, t) for stamp in stamps),
        retry=Indication.INDETERMINATE in indications,
    )


def verification_text(view: VerificationView, translations: gettext.NullTranslations) -> str:
    """The result page as plain text, for "Read in Spanish" (BRG-UX-001 §4.2): the summary,
    then each signature and each document time-stamp with its explanation and details.
    ``view`` must have been built with the same ``translations``."""

    def block(result: ResultView) -> str:
        lines = [result.title, *([result.explanation] if result.explanation else [])]
        return "\n".join(lines + [f"{d.label}: {d.value}" for d in result.details])

    blocks = [view.summary, *(block(signature) for signature in view.signatures)]
    if view.timestamps:
        blocks.append(translations.gettext("Document time-stamps"))
        blocks += [block(stamp) for stamp in view.timestamps]
    return "\n\n".join(blocks)


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
    document: DocumentInfo | int,
    check: SignerCheck,
    level: SignatureLevel,
    translations: gettext.NullTranslations | None = None,
    packaging: Packaging = None,
) -> tuple[Detail, ...]:
    """What the PIN dialog shows before the PIN is sent (P-01, BRG-UX-001 §3.3).

    ``document`` is the document, or the number of documents of a batch (CU-04), whose list
    the user has just confirmed; ``packaging`` the format of a document that is not signed in
    PAdES (CU-05). ``translations`` gives it in another language: Quechua users can read it
    in Spanish.
    """
    t = translations or catalogue()
    certificate = check.chain[-1]
    rows = []
    if isinstance(document, int):
        rows.append(
            Detail(
                t.gettext("Documents"),
                t.ngettext("{n} document", "{n} documents", document).format(n=document),
            )
        )
    elif document.kind is DocumentKind.PDF:
        pages = document.pages or 0
        rows.append(
            Detail(
                t.gettext("Document"),
                t.ngettext("{name} ({n} page)", "{name} ({n} pages)", pages).format(
                    name=document.path.name, n=pages
                ),
            )
        )
    else:
        rows.append(
            Detail(
                t.gettext("Document"),
                f"{document.path.name} ({file_size(document.size, t)})",
            )
        )
        rows.append(Detail("SHA-256", grouped_digest(document.sha256)))
    if packaging is not None:
        rows.append(Detail(t.gettext(messages.REPORT_FORMAT), packaging_title(packaging, t)))
    rows.append(Detail(t.gettext(messages.REPORT_SIGNER), common_name(certificate)))
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


# -- Diagnosis (CU-07, RF-007) ---------------------------------------------------------------------

DIAGNOSIS_TITLES = {
    Step.PCSC: N_("Smart Card Service (pcscd)"),
    Step.READER: N_("Card Reader"),
    Step.CARD: N_("DNIe"),
    Step.CERTIFICATE: N_("Signing Certificate"),
    Step.VALIDATION: N_("Trust and Revocation"),
    Step.TSA: N_("Time-Stamping Authority"),
}
DIAGNOSIS_ICONS = {
    DiagnosisStatus.OK: ("object-select-symbolic", "success"),
    DiagnosisStatus.WARNING: ("dialog-warning-symbolic", "warning"),
    DiagnosisStatus.ERROR: ("dialog-error-symbolic", "error"),
    DiagnosisStatus.SKIPPED: ("action-unavailable-symbolic", "dimmed"),
}
DIAGNOSIS_MARKS = {
    DiagnosisStatus.OK: "✓",
    DiagnosisStatus.WARNING: "⚠",
    DiagnosisStatus.ERROR: "✗",
    DiagnosisStatus.SKIPPED: "·",
}


def _local_date(iso: str) -> str:
    return dt.datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d")


def diagnosis_text(result: DiagnosisResult) -> str:
    """What a step found and, when something is wrong, what to do (CU-07 step 2)."""
    step, status, facts = result.step, result.status, result.facts
    if status is DiagnosisStatus.SKIPPED and step is not Step.TSA:
        return _("Not checked: an earlier step failed.")
    if result.code is not None and not (step is Step.CERTIFICATE and result.code == "ERR-211"):
        return explain_error(result.code, catalogue()) or ""
    if step is Step.PCSC:
        if status is DiagnosisStatus.OK:
            return _("The service is running.")
        return _(
            "The service is not running. Install it and start it: "
            "sudo apt install pcscd && sudo systemctl enable --now pcscd.socket"
        )
    if step is Step.READER:
        if status is DiagnosisStatus.OK:
            return _("Connected: {readers}.").format(readers=facts.get("readers", ""))
        return _("No card reader is connected. Connect a USB smart card reader.")
    if step is Step.CARD:
        if status is DiagnosisStatus.OK:
            return _("A DNIe is in {reader}.").format(reader=facts.get("reader", ""))
        if "atr" in facts:
            return _(
                "The card in the reader is not a supported DNIe (ATR {atr}). Only the DNIe "
                "version 2 is supported for now."
            ).format(atr=facts["atr"])
        return _("There is no card in the reader. Insert your DNIe.")
    if step is Step.CERTIFICATE:
        signer, date = facts.get("signer", ""), _local_date(facts["expires"])
        days = int(facts.get("days", "0"))
        if status is DiagnosisStatus.ERROR:
            return _(
                "{signer}: the certificate expired on {date}. Renew it on RENIEC's Ciudadano "
                "Digital platform."
            ).format(signer=signer, date=date)
        if status is DiagnosisStatus.WARNING:
            return ngettext(
                "{signer}: the certificate expires on {date}, in {n} day. Renew it on RENIEC's "
                "Ciudadano Digital platform.",
                "{signer}: the certificate expires on {date}, in {n} days. Renew it on "
                "RENIEC's Ciudadano Digital platform.",
                days,
            ).format(signer=signer, date=date, n=days)
        return _("{signer}, valid until {date}.").format(signer=signer, date=date)
    if step is Step.VALIDATION:
        if status is DiagnosisStatus.OK:
            return _("Your certificate is trusted and was not revoked (checked online).")
        if facts.get("note") == "offline":
            return _("Revocation was not checked: berigna is working without network access.")
        return _(
            "RENIEC could not be asked whether your certificate is revoked. Check the "
            "connection; meanwhile only basic signatures (B-B) are possible."
        )
    # Step.TSA
    if status is DiagnosisStatus.OK:
        return _("The time-stamping authority answered and is trusted.")
    if facts.get("configured") == "False":
        return _(
            "No time-stamping authority is configured: only basic signatures (B-B) are "
            "possible. Configure one in Preferences → Network."
        )
    return _("Not checked: berigna is working without network access.")


def diagnosis_report(results: list[DiagnosisResult], version: str, system: str) -> str:
    """The report to copy for support (CU-07 step 3): no PIN, the DNI only masked."""
    lines = [
        _("berigna {version} diagnosis, {moment}").format(
            version=version, moment=format_time(dt.datetime.now(dt.UTC), _)
        ),
        system,
        "",
    ]
    for result in results:
        mark = DIAGNOSIS_MARKS[result.status]
        lines.append(f"[{mark}] {_(DIAGNOSIS_TITLES[result.step])}: {diagnosis_text(result)}")
    return mask_numbers("\n".join(lines)) + "\n"


def failure_report(failure: str, version: str, system: str) -> str:
    """The report of an unexpected failure to copy for support (R-DES-11): no PIN, the DNI
    only masked. ``failure`` is the pending report of :mod:`berigna.core.crashes`."""
    lines = [
        _("berigna {version} failure report, {moment}").format(
            version=version, moment=format_time(dt.datetime.now(dt.UTC), _)
        ),
        system,
        "",
        failure,
    ]
    return mask_numbers("\n".join(lines)) + "\n"


# -- Trust store (RF-060) --------------------------------------------------------------------------

TRUST_SOURCES = (
    ("bundled", N_("Included in berigna")),
    ("tsl", N_("From the INDECOPI trusted list")),
    ("user", N_("Added by you")),
)


def _trust_source(entry: TrustedCertificate) -> str:
    if entry.user_added:
        return "user"
    return "tsl" if entry.hierarchy == "TSL" else "bundled"


def trust_store_view(store: TrustStore) -> list[tuple[str, list[tuple[str, str]]]]:
    """The certificates berigna trusts, by where they come from: (group title, [(name,
    details)]). The details give the role, the validity and the SHA-256 in groups of four, to
    compare with an official source."""
    groups: list[tuple[str, list[tuple[str, str]]]] = []
    for key, title in TRUST_SOURCES:
        rows = []
        for entry in store.entries:
            if _trust_source(entry) != key:
                continue
            certificate = entry.certificate
            # What the certificate is, not its role: a CA listed in the TSL is an anchor even
            # when it is an intermediate (ADR-0022).
            role = _("Root") if certificate.subject == certificate.issuer else _("Intermediate")
            until = certificate.not_valid_after_utc.astimezone().strftime("%Y-%m-%d")
            fingerprint = " ".join(
                entry.sha256.upper()[i : i + 4] for i in range(0, len(entry.sha256), 4)
            )
            details = _("{role} · valid until {date}").format(role=role, date=until)
            if entry.hierarchy and key == "bundled":
                details += f" · {entry.hierarchy}"
            rows.append((display_name(certificate.subject), f"{details}\nSHA-256 {fingerprint}"))
        if rows:
            groups.append((_(title), sorted(rows)))
    return groups
