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
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.pades import SignatureLevel
from berigna.core.formats.xades import XadesPackaging
from berigna.core.i18n import Language, translations
from berigna.core.signing import SignResult
from berigna.core.validation import SignerCheck
from berigna.ui import i18n
from berigna.ui.presentation import (
    PACKAGING_DESCRIPTIONS,
    PACKAGING_NOTES,
    file_details,
    file_size,
    level_title,
    packaging_description,
    packaging_note,
    packagings_for,
    pin_summary,
    pin_warnings,
    signed_summary,
)

NOW = dt.datetime.now(dt.UTC)


def _certificate(serial: str | None, days_left: int = 400) -> x509.Certificate:
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
        .not_valid_after(NOW + dt.timedelta(days=days_left, hours=1))
        .sign(key, hashes.SHA256())
    )


def _check(
    serial: str | None = "PNOPE-12345678", checked: bool = True, days_left: int = 400
) -> SignerCheck:
    return SignerCheck(checked, (_certificate(serial, days_left),), NOW)


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


@pytest.mark.parametrize(
    ("days_left", "warned"), [(400, False), (30, False), (29, True), (1, True)]
)
def test_certificate_about_to_expire_is_warned_before_the_pin(days_left: int, warned: bool) -> None:
    """Less than a month left (decision of 2026-10-28): the PIN dialog says when and where to
    renew it."""
    check = _check(days_left=days_left)
    assert check.expires_soon is warned
    warnings = pin_warnings(check, None)
    if not warned:
        assert warnings == ()
        return
    date = check.expires.astimezone().strftime("%Y-%m-%d")
    unit = "día" if days_left == 1 else "días"
    assert warnings == (
        f"Tu certificado de firma vence el {date}, dentro de {days_left} {unit}. Renuévalo en "
        "la plataforma Ciudadano Digital de RENIEC para seguir firmando.",
    )


# -- Files that are not PDF (CU-05) ----------------------------------------------------------------

FILE = DocumentInfo(Path("documentos/planilla.csv"), DocumentKind.OTHER, 1234567, "ab" * 32)


@pytest.mark.parametrize(
    ("size", "text"),
    [
        (0, "0 bytes"),
        (1, "1 byte"),
        (999, "999 bytes"),
        (1024, "1,0 kB (1 024 bytes)"),
        (1234567, "1,2 MB (1 234 567 bytes)"),
        (3 * 10**9, "3,0 GB (3 000 000 000 bytes)"),
    ],
)
def test_file_size(size: int, text: str) -> None:
    assert file_size(size) == text


def test_file_details_identify_the_file() -> None:
    """WYSIWYS (CU-05 step 3): what the user checks before signing what cannot be shown."""
    rows = {r.label: r.value for r in file_details(FILE, "Hoja de cálculo CSV")}
    assert rows == {
        "Nombre": "planilla.csv",
        "Tamaño": "1,2 MB (1 234 567 bytes)",
        "Tipo": "Hoja de cálculo CSV",
        "SHA-256": " ".join(["ABAB"] * 16),
    }


def test_proposed_packagings() -> None:
    """CU-05 step 2: XAdES enveloped first for XML, CAdES detached first for the rest."""
    assert packagings_for(DocumentKind.XML)[0] is XadesPackaging.ENVELOPED
    assert CadesPackaging.DETACHED in packagings_for(DocumentKind.XML)
    assert packagings_for(DocumentKind.OTHER) == (
        CadesPackaging.DETACHED,
        CadesPackaging.ENVELOPING,
    )
    assert set(PACKAGING_DESCRIPTIONS) == set(packagings_for(DocumentKind.XML))


def test_the_differences_with_firma_peru_are_said() -> None:
    """The standard names are kept, and the user is told where Firma Perú differs: it does
    not recognize .p7m nor validate .xsig (BRG-CAL-006 §3.10, decision of 2026-11-03)."""
    assert set(PACKAGING_NOTES) == {CadesPackaging.ENVELOPING, XadesPackaging.DETACHED}
    assert packaging_note(CadesPackaging.DETACHED) is None
    enveloping = packaging_description(CadesPackaging.ENVELOPING)
    assert enveloping.startswith("Un archivo .p7m contiene la firma")
    assert ".p7s" in enveloping
    assert "Firma Perú" in enveloping
    assert "Firma Perú" not in packaging_description(XadesPackaging.ENVELOPED)


def test_pin_summary_of_a_file_and_of_a_batch() -> None:
    rows = {
        r.label: r.value
        for r in pin_summary(
            FILE, _check(), SignatureLevel.B_B, packaging=CadesPackaging.ENVELOPING
        )
    }
    assert rows["Documento"] == "planilla.csv (1,2 MB (1 234 567 bytes))"
    assert rows["SHA-256"].startswith("ABAB ABAB")
    assert rows["Formato"] == "CAdES, envolvente (.p7m)"
    batch = {r.label: r.value for r in pin_summary(4, _check(), SignatureLevel.B_B)}
    assert batch["Documentos"] == "4 documentos"
    assert "Formato" not in batch
