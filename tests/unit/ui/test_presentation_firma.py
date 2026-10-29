# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Texts of the signing flow (BRG-UX-001 §3.3 and §4, P-07)."""

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from berigna.core.documents import DocumentInfo, DocumentKind
from berigna.core.formats.pades import SignatureLevel
from berigna.core.i18n import Language, translations
from berigna.core.signing import SignResult
from berigna.core.validation import SignerCheck
from berigna.ui import i18n
from berigna.ui.presentation import (
    level_title,
    pin_summary,
    pin_warnings,
    signed_summary,
)

NOW = dt.datetime.now(dt.UTC)


def _certificate(serial: str | None) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ LOPEZ JUAN FIR 12345678 hard")]
    if serial is not None:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial))
    name = x509.Name(attributes)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def _check(serial: str | None = "PNOPE-12345678", checked: bool = True) -> SignerCheck:
    return SignerCheck(checked, (_certificate(serial),), NOW)


DOCUMENT = DocumentInfo(Path("documentos/contrato.pdf"), DocumentKind.PDF, 10, "00", 3)


def test_level_title_puts_plain_words_first() -> None:
    assert level_title(SignatureLevel.B_LT) == "Validación a largo plazo (B-LT)"
    assert level_title(SignatureLevel.B_B) == "Básica (B-B)"


def test_pin_summary_masks_the_dni() -> None:
    rows = {r.label: r.value for r in pin_summary(DOCUMENT, _check(), SignatureLevel.B_T)}
    assert rows == {
        "Documento": "contrato.pdf (3 páginas)",
        "Firmante": "PEREZ LOPEZ JUAN FIR ****5678 hard",
        "DNI": "****5678",
        "Nivel": "Con sello de tiempo (B-T)",
    }
    without = pin_summary(DOCUMENT, _check(serial=None), SignatureLevel.B_B)
    assert "DNI" not in {r.label for r in without}


def test_pin_summary_in_spanish_from_quechua() -> None:
    """BRG-UX-001 §4.2: Quechua users can read the summary in Spanish."""
    try:
        i18n.set_language(Language.QUZ_PE)
        rows = pin_summary(DOCUMENT, _check(), SignatureLevel.B_B, translations(Language.ES_PE))
        assert rows[0].label == "Documento"
    finally:
        i18n.set_language(Language.ES_PE)


@pytest.mark.parametrize(
    ("tries", "checked", "expected"),
    [
        (None, True, []),
        (2, True, ["El PIN no era correcto. Te quedan 2 intentos antes de que el PIN se bloquee."]),
        (1, True, ["El PIN no era correcto. Te queda 1 intento antes de que el PIN se bloquee."]),
        (
            None,
            False,
            [
                "No se pudo comprobar en línea si tu certificado está revocado; por eso "
                "solo es posible una firma básica."
            ],
        ),
    ],
)
def test_pin_warnings(tries: int | None, checked: bool, expected: list[str]) -> None:
    assert list(pin_warnings(_check(checked=checked), tries)) == expected


@pytest.mark.parametrize(
    ("reached", "requested", "ending"),
    [
        (SignatureLevel.B_LT, SignatureLevel.B_LT, "nivel Validación a largo plazo (B-LT)."),
        (SignatureLevel.B_T, SignatureLevel.B_LT, "los servicios de revocación no respondieron."),
        (SignatureLevel.B_LT, SignatureLevel.B_LTA, "sello de tiempo del documento."),
    ],
)
def test_signed_summary(reached: SignatureLevel, requested: SignatureLevel, ending: str) -> None:
    result = SignResult(Path("documentos/contrato-firmado.pdf"), "00", reached, True, "technical")
    text = signed_summary(result, requested)
    assert text.startswith("Guardado como contrato-firmado.pdf, nivel ")
    assert text.endswith(ending)
    assert "technical" not in text
