# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Machine-readable verification report (RF-054).

Codes are the normalised ETSI ones; explanations go in both languages of berigna 1.0
(ADR-0015). A Quechua explanation still waiting for the translators is ``null``, never a
Spanish or English stand-in. Times are ISO 8601 in UTC (ADR-0011 §6). Of the signer's national
identity number (in the serial number and in the common name) only the last four digits are
kept.
"""

import datetime as dt
import json
from typing import Any

from cryptography import x509

import berigna
from berigna.core.i18n import Language, translations
from berigna.core.report.explanations import (
    common_name,
    explain_signature,
    explain_timestamp,
    masked_id,
)
from berigna.core.trust import TrustStore
from berigna.core.validation import PdfVerification, TimestampReport

SCHEMA = "berigna-verification-report/1"


def _iso(moment: dt.datetime | None) -> str | None:
    if moment is None:
        return None
    return moment.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def _signer(certificate: x509.Certificate | None) -> dict[str, Any] | None:
    if certificate is None:
        return None
    return {
        "name": common_name(certificate),
        "id_masked": masked_id(certificate),
        "cert_serial": format(certificate.serial_number, "x"),
        "issuer": certificate.issuer.rfc4514_string(),
    }


def _explanations(texts: dict[Language, str | None]) -> dict[str, str | None]:
    return {language.value: text for language, text in texts.items()}


def _timestamp(report: TimestampReport | None) -> dict[str, Any] | None:
    if report is None:
        return None
    return {
        "indication": report.indication.value,
        "sub_indication": report.subindication,
        "time": _iso(report.time),
        "tsa": common_name(report.tsa) if report.tsa is not None else None,
    }


def _catalogues() -> dict[Language, Any]:
    return {
        Language.ES_PE: translations(Language.ES_PE),
        Language.QUZ_PE: translations(Language.QUZ_PE, strict=True),
    }


def report_data(
    verification: PdfVerification,
    *,
    file_name: str,
    file_sha256: str,
    store: TrustStore,
) -> dict[str, Any]:
    """The report of :func:`berigna.core.validation.verify_pdf` as a JSON-ready dict."""
    catalogues = _catalogues()
    user_roots = any(entry.user_added for entry in store.entries)
    signatures = []
    for report in verification.signatures:
        signatures.append(
            {
                "id": report.field_name,
                "format": "PAdES",
                "subfilter": report.subfilter,
                "signer": _signer(report.signer),
                "signing_time": {
                    "claimed": _iso(report.claimed_signing_time),
                    "timestamp": _timestamp(report.timestamp),
                },
                "indication": report.indication.value,
                "sub_indication": report.subindication,
                "covers_whole_document": report.covers_whole_document,
                "modifications_after": report.modifications.value,
                "signed_revision_length": report.signed_revision_length,
                "explanation": _explanations(
                    {lang: explain_signature(report, cat) for lang, cat in catalogues.items()}
                ),
            }
        )
    stamps = [
        {
            "id": stamp.field_name,
            **(_timestamp(stamp) or {}),
            "explanation": _explanations(
                {lang: explain_timestamp(stamp, cat) for lang, cat in catalogues.items()}
            ),
        }
        for stamp in verification.document_timestamps
    ]
    return {
        "schema": SCHEMA,
        "berigna_version": berigna.__version__,
        "validated_at": _iso(verification.moment),
        "languages": [language.value for language in catalogues],
        "file": {"name": file_name, "sha256": file_sha256},
        "trust_store": {"anchors": len(store.entries), "user_anchors": user_roots},
        "signatures": signatures,
        "document_timestamps": stamps,
    }


def dumps(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
