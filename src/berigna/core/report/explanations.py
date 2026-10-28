# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Plain-language explanations of verification results and errors (RF-053, ADR-0011 §7).

The core returns codes; this module turns them into sentences of the requested catalogue. With
a strict Quechua catalogue (:func:`berigna.core.i18n.translations`), a sentence still waiting
for the translators makes the whole explanation ``None`` instead of mixing languages.
"""

import datetime as dt
import gettext
import re

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


def format_time(moment: dt.datetime) -> str:
    """dd/mm/yyyy hh:mm in UTC: the same in both languages and unambiguous in Peru."""
    return moment.astimezone(dt.UTC).strftime("%d/%m/%Y %H:%M UTC")


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
                _(catalogue, messages.TIME_CERTIFIED).format(time=format_time(stamp.time))
            )
        elif report.claimed_signing_time is not None:
            when = format_time(report.claimed_signing_time)
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
            when = format_time(report.time)
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
