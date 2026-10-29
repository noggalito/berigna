# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Human-readable PDF verification report (RF-054)."""

import io
import shutil
import subprocess
from pathlib import Path

import pytest
from pyhanko.pdf_utils.reader import PdfFileReader

from berigna.core.i18n import Language
from berigna.core.report import pdf_report as module
from berigna.core.report.pdf_report import pdf_report
from berigna.core.trust import TrustedCertificate, TrustStore
from berigna.core.validation import (
    Indication,
    Modifications,
    PdfSignatureReport,
    PdfVerification,
    TimestampReport,
)
from support.pki import NOW, Pki, build_pki


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _text(pdf: bytes, tmp_path: Path) -> str:
    if shutil.which("pdftotext") is None:
        pytest.fail("poppler-utils is needed: apt install poppler-utils")
    path = tmp_path / "informe.pdf"
    path.write_bytes(pdf)
    result = subprocess.run(  # noqa: S603 - fixed arguments
        ["pdftotext", "-layout", str(path), "-"],  # noqa: S607 - the system's pdftotext
        capture_output=True,
        check=True,
        text=True,
    )
    return " ".join(result.stdout.split())


def _verification(pki: Pki) -> PdfVerification:
    leaf = pki.leaf("PEREZ QUISPE JUAN")
    stamp = TimestampReport(Indication.TOTAL_PASSED, None, NOW, pki.ca)
    good = PdfSignatureReport(
        "FirmaBerigna1",
        Indication.TOTAL_PASSED,
        None,
        leaf,
        NOW,
        "/ETSI.CAdES.detached",
        False,
        Modifications.LTA_UPDATES,
        4321,
        timestamp=stamp,
    )
    damaged = PdfSignatureReport(
        "Firma2",
        Indication.TOTAL_FAILED,
        "FORMAT_FAILURE",
        None,
        None,
        "",
        False,
        Modifications.OTHER,
        0,
    )
    document = TimestampReport(Indication.TOTAL_PASSED, None, NOW, None, "SelloBerigna1")
    return PdfVerification((good, damaged), (document,), NOW)


def _report(
    pki: Pki, language: Language = Language.ES_PE, store: TrustStore | None = None
) -> bytes:
    return pdf_report(
        _verification(pki),
        file_name="contrato-firmado.pdf",
        file_sha256="ab" * 32,
        store=store or pki.store,
        language=language,
    )


def test_spanish_report_contents(pki: Pki, tmp_path: Path) -> None:
    text = _text(_report(pki), tmp_path)
    for expected in (
        "Informe de verificación de firmas",
        "contrato-firmado.pdf",
        " ".join(["abababab"] * 8),
        "2 certificados de la infraestructura oficial (IOFE)",
        "Firma 1 de 2: FirmaBerigna1",
        "La firma es válida. Firmado por PEREZ QUISPE JUAN.",
        "TOTAL-PASSED",
        "TEST ECEP CA Class 2",
        "Primeros 4321 bytes del archivo",
        "Firma 2 de 2: Firma2",
        "TOTAL-FAILED / FORMAT_FAILURE",
        "Ninguno",
        "Sellos de tiempo de documento",
        "SelloBerigna1",
        "Informe generado por berigna",
        "Página 1",
    ):
        assert expected in text, expected
    assert "prevalece" not in text


def test_quechua_report_says_spanish_prevails(pki: Pki, tmp_path: Path) -> None:
    text = _text(_report(pki, Language.QUZ_PE), tmp_path)
    assert "prevalece la versión en español (es_PE)" in text
    assert "Traducción sin revisar por hablantes." in text


def test_user_anchors_are_disclosed(pki: Pki, tmp_path: Path) -> None:
    store = TrustStore([TrustedCertificate(pki.root, "root", "usuario", user_added=True)])
    assert "incluidas raíces que añadiste tú" in _text(_report(pki, store=store), tmp_path)


def test_document_without_signatures(pki: Pki, tmp_path: Path) -> None:
    empty = PdfVerification((), (), NOW)
    pdf = pdf_report(empty, file_name="a.pdf", file_sha256="00", store=pki.store)
    assert "Este documento no tiene firmas." in _text(pdf, tmp_path)


def test_report_is_reproducible_and_valid_pdf(pki: Pki) -> None:
    first, second = _report(pki), _report(pki)
    assert first == second  # invariant mode: same result, same bytes
    assert PdfFileReader(io.BytesIO(first)).root["/Pages"]["/Count"] >= 1


def test_without_dejavu_helvetica_is_used(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert module._fonts(tmp_path) == ("Helvetica", "Helvetica-Bold")
    monkeypatch.setattr(module, "_fonts", lambda: ("Helvetica", "Helvetica-Bold"))
    assert "Informe de verificación de firmas" in _text(_report(pki), tmp_path)
