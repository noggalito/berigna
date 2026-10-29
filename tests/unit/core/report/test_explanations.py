# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Plain-language explanations (RF-053) in es_PE, and nothing mixed in for Quechua."""

import datetime as dt

import pytest
from cryptography import x509

from berigna.core.i18n import Language, translations
from berigna.core.report.explanations import (
    explain_error,
    explain_signature,
    explain_timestamp,
    format_time,
    subindication_key,
    utc_offset,
)
from berigna.core.validation import (
    Indication,
    Modifications,
    PdfSignatureReport,
    TimestampReport,
)
from support.pki import NOW, Pki, build_pki

SPANISH = translations(Language.ES_PE)
WHEN = format_time(NOW, SPANISH.gettext)
STRICT_QUECHUA = translations(Language.QUZ_PE, strict=True)


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _report(signer: x509.Certificate | None, **changes: object) -> PdfSignatureReport:
    values: dict[str, object] = {
        "field_name": "FirmaBerigna1",
        "indication": Indication.TOTAL_PASSED,
        "subindication": None,
        "signer": signer,
        "claimed_signing_time": NOW,
        "subfilter": "/ETSI.CAdES.detached",
        "covers_whole_document": True,
        "modifications": Modifications.NONE,
        "signed_revision_length": 100,
    }
    values.update(changes)
    return PdfSignatureReport(**values)  # type: ignore[arg-type]


def test_valid_signature_with_certified_time(pki: Pki) -> None:
    stamp = TimestampReport(Indication.TOTAL_PASSED, None, NOW, None)
    text = explain_signature(_report(pki.leaf("JUAN PEREZ"), timestamp=stamp), SPANISH)
    assert text == (
        "La firma es válida. Firmado por JUAN PEREZ. "
        f"La hora de la firma, {WHEN}, está certificada por una autoridad de "
        "sellado de tiempo. El documento no se ha modificado desde que se firmó."
    )


def test_claimed_time_is_said_to_be_uncertified(pki: Pki) -> None:
    text = explain_signature(_report(pki.leaf("FIRMANTE")), SPANISH)
    assert text is not None
    assert "la declaró el equipo del firmante y no está certificada" in text


def test_invalid_timestamp_falls_back_to_the_claimed_time(pki: Pki) -> None:
    stamp = TimestampReport(Indication.INDETERMINATE, "NO_CERTIFICATE_CHAIN_FOUND", NOW, None)
    text = explain_signature(_report(pki.leaf("FIRMANTE"), timestamp=stamp), SPANISH)
    assert text is not None
    assert "no está certificada" in text


def test_failure_with_its_reason_and_later_changes(pki: Pki) -> None:
    report = _report(
        pki.leaf("FIRMANTE"),
        indication=Indication.INDETERMINATE,
        subindication="REVOKED_NO_POE",
        claimed_signing_time=None,
        modifications=Modifications.OTHER,
    )
    text = explain_signature(report, SPANISH, user_anchor=True)
    assert text is not None
    assert text.startswith("No se pudo determinar si la firma es válida. El certificado")
    assert "Abre la versión firmada" in text
    assert text.endswith(
        "La cadena termina en un certificado raíz que añadiste tú, no en uno oficial."
    )


def test_damaged_signature_says_nothing_about_the_content() -> None:
    report = _report(
        None,
        indication=Indication.TOTAL_FAILED,
        subindication="FORMAT_FAILURE",
        claimed_signing_time=None,
        modifications=Modifications.OTHER,
    )
    assert explain_signature(report, SPANISH) == (
        "La firma no es válida. La firma está dañada o no tiene el formato esperado."
    )


def test_unknown_subindication_gets_the_generic_text() -> None:
    assert subindication_key(Indication.INDETERMINATE, "SOMETHING_NEW") == "INDETERMINATE:GENERIC"
    assert subindication_key(Indication.TOTAL_PASSED, None) is None
    assert (
        subindication_key(Indication.TOTAL_FAILED, "NOT_YET_VALID") == "TOTAL_FAILED:NOT_YET_VALID"
    )


def test_document_timestamp() -> None:
    stamp = TimestampReport(Indication.TOTAL_PASSED, None, NOW, None, "SelloBerigna1")
    assert explain_timestamp(stamp, SPANISH) == (
        f"La firma es válida. Sello de tiempo de documento emitido el {WHEN}."
    )
    assert explain_timestamp(
        TimestampReport(Indication.TOTAL_FAILED, "FORMAT_FAILURE", None, None), SPANISH
    ) == ("La firma no es válida. La firma está dañada o no tiene el formato esperado.")


def test_errors() -> None:
    assert explain_error("ERR-303", SPANISH) == "Se canceló la firma. El PIN no se envió."
    assert explain_error("ERR-999", SPANISH) == "Error inesperado."


def test_quechua_explanations(pki: Pki) -> None:
    text = explain_signature(_report(pki.leaf("FIRMANTE")), STRICT_QUECHUA)
    assert text is not None
    assert text.startswith("Firmaqa chiqaqmi. FIRMANTE firmarqan.")
    assert explain_error("ERR-101", STRICT_QUECHUA) == "DNIeykita lectorman satiy."


def test_pending_quechua_gives_no_explanation_rather_than_a_mixed_one(
    pki: Pki, pending_quechua: None
) -> None:
    strict = translations(Language.QUZ_PE, strict=True)
    assert explain_signature(_report(pki.leaf("FIRMANTE")), strict) is None
    assert (
        explain_timestamp(TimestampReport(Indication.TOTAL_PASSED, None, NOW, None), strict) is None
    )
    assert explain_error("ERR-101", strict) is None


def test_identity_numbers_are_masked(pki: Pki) -> None:
    from berigna.core.report.explanations import mask_numbers

    assert (
        mask_numbers("PEREZ QUISPE JUAN FIR 12345678 hard") == "PEREZ QUISPE JUAN FIR ****5678 hard"
    )
    assert mask_numbers("EMPRESA FAU 20123456789 soft") == "EMPRESA FAU ****6789 soft"
    assert mask_numbers("CLASS 2 II") == "CLASS 2 II"
    text = explain_signature(_report(pki.leaf("PEREZ JUAN FIR 12345678 hard")), SPANISH)
    assert text is not None
    assert "Firmado por PEREZ JUAN FIR ****5678 hard." in text
    assert "12345678" not in text


def test_times_use_iso_dates_si_hours_and_the_offset() -> None:
    lima = dt.timezone(dt.timedelta(hours=-5))
    moment = dt.datetime(2026, 10, 28, 23, 47, tzinfo=dt.UTC)
    spanish = SPANISH.gettext
    assert format_time(moment, spanish, lima) == "2026-10-28 a las 18h47 UTC-5"
    assert format_time(moment, spanish, dt.UTC) == "2026-10-28 a las 23h47 UTC"
    india = dt.timezone(dt.timedelta(hours=5, minutes=30))
    assert format_time(moment, zone=india) == "2026-10-29 at 05h17 UTC+5:30"
    # Without a zone, the local one, with its offset: the moment stays unambiguous.
    assert format_time(moment).endswith(utc_offset(moment.astimezone()))
