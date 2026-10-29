# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Plain-language explanations of verification results and errors (RF-053, ADR-0011 §7).

The core returns codes; this module turns them into sentences of the requested catalogue. With
a strict Quechua catalogue (:func:`berigna.core.i18n.translations`), a sentence still waiting
for the translators makes the whole explanation ``None`` instead of mixing languages.
"""

import datetime as dt
import gettext
import re
from collections.abc import Callable
from functools import partial

from cryptography import x509
from cryptography.x509.oid import NameOID

from berigna.core.report import messages
from berigna.core.validation import Indication, PdfSignatureReport, TimestampReport


class _UntranslatedError(Exception):
    pass


def _(catalogue: gettext.NullTranslations, message: str) -> str:
    text = catalogue.gettext(message)
    if text == message:  # no catalogue has it: never show the English source
        raise _UntranslatedError(message)
    return text


def utc_offset(moment: dt.datetime) -> str:
    """The offset of an aware ``moment`` as UTC-5, UTC+5:30 or UTC."""
    minutes = int((moment.utcoffset() or dt.timedelta(0)).total_seconds()) // 60
    if minutes == 0:
        return "UTC"
    hours, rest = divmod(abs(minutes), 60)
    return f"UTC{'+' if minutes > 0 else '-'}{hours}" + (f":{rest:02d}" if rest else "")


def format_time(
    moment: dt.datetime,
    gettext_: Callable[[str], str] = lambda message: message,
    zone: dt.tzinfo | None = None,
) -> str:
    """ISO 8601 date, hours and minutes with the SI symbol h, and the offset from UTC, in
    ``zone`` (by default the local one): 2026-10-28 a las 18h47 UTC-5."""
    local = moment.astimezone(zone)
    return gettext_(messages.MOMENT).format(
        date=local.strftime("%Y-%m-%d"),
        hour=local.strftime("%H"),
        minute=local.strftime("%M"),
        zone=utc_offset(local),
    )


def mask_numbers(text: str) -> str:
    """Hide all but the last four digits of every run of five or more digits.

    The common name of a DNIe certificate carries the full national identity number
    ("… FIR 12345678 hard"), and company certificates their RUC: reports keep the last four.
    """
    return re.sub(r"\d{5,}", lambda match: "****" + match.group()[-4:], text)


def display_name(name: x509.Name) -> str:
    """The common name of ``name`` (or the whole name), with long numbers masked."""
    names = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return mask_numbers(str(names[0].value) if names else name.rfc4514_string())


def common_name(certificate: x509.Certificate) -> str:
    return display_name(certificate.subject)


def identity_number(certificate: x509.Certificate) -> str | None:
    """The identity number of the subject (the digits of serialNumber, "PNOPE-12345678")."""
    serials = certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    digits = re.sub(r"\D", "", str(serials[0].value)) if serials else ""
    return digits if len(digits) >= 4 else None


def masked_id(certificate: x509.Certificate) -> str | None:
    """The identity number of the subject, all but its last four digits hidden."""
    digits = identity_number(certificate)
    return f"****{digits[-4:]}" if digits else None


def subindication_key(indication: Indication, subindication: str | None) -> str | None:
    """Key of :data:`messages.SUBINDICATIONS`; unknown subindications map to GENERIC."""
    if subindication is None:
        return None
    key = f"{indication.name}:{subindication}"
    return key if key in messages.SUBINDICATIONS else "INDETERMINATE:GENERIC"


def _result(
    catalogue: gettext.NullTranslations, indication: Indication, subindication: str | None
) -> list[str]:
    sentences = [_(catalogue, messages.INDICATIONS[indication])]
    key = subindication_key(indication, subindication)
    if key is not None:
        sentences.append(_(catalogue, messages.SUBINDICATIONS[key]))
    return sentences


def explain_signature(
    report: PdfSignatureReport,
    catalogue: gettext.NullTranslations,
    *,
    user_anchor: bool = False,
) -> str | None:
    """Explanation of one signature; ``None`` if the catalogue lacks a sentence."""
    try:
        sentences = _result(catalogue, report.indication, report.subindication)
        strict = partial(_, catalogue)
        if report.signer is not None:
            name = common_name(report.signer)
            sentences.append(_(catalogue, messages.SIGNED_BY).format(name=name))
        stamp = report.timestamp
        if (
            stamp is not None
            and stamp.time is not None
            and stamp.indication is Indication.TOTAL_PASSED
        ):
            sentences.append(
                _(catalogue, messages.TIME_CERTIFIED).format(time=format_time(stamp.time, strict))
            )
        elif report.claimed_signing_time is not None:
            when = format_time(report.claimed_signing_time, strict)
            sentences.append(_(catalogue, messages.TIME_CLAIMED).format(time=when))
        if report.signer is not None:  # a format failure says nothing about the content
            sentences.append(_(catalogue, messages.MODIFICATIONS[report.modifications]))
        if user_anchor:
            sentences.append(_(catalogue, messages.USER_ANCHOR))
    except _UntranslatedError:
        return None
    return " ".join(sentences)


def explain_timestamp(report: TimestampReport, catalogue: gettext.NullTranslations) -> str | None:
    """Explanation of a document time-stamp; ``None`` if the catalogue lacks a sentence."""
    try:
        sentences = _result(catalogue, report.indication, report.subindication)
        if report.time is not None:
            when = format_time(report.time, partial(_, catalogue))
            sentences.append(_(catalogue, messages.DOCUMENT_TIMESTAMP).format(time=when))
    except _UntranslatedError:
        return None
    return " ".join(sentences)


def explain_error(code: str, catalogue: gettext.NullTranslations) -> str | None:
    """Message for an ``ERR-xxx`` code; unknown codes get the ERR-000 message."""
    try:
        return _(catalogue, messages.ERRORS.get(code, messages.ERRORS["ERR-000"]))
    except _UntranslatedError:
        return None
