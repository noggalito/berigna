# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
import datetime as dt
from pathlib import Path

import pytest

from berigna.core.documents import DocumentInfo, DocumentKind
from berigna.core.i18n import Language, translations
from berigna.core.report.explanations import format_time
from berigna.core.token.monitor import DeviceState, DeviceStatus
from berigna.core.trust import TrustStore
from berigna.core.validation import Indication, Modifications, PdfVerification, verify_pdf
from berigna.core.validation.pdf import PdfSignatureReport, TimestampReport
from berigna.ui.presentation import (
    VerificationView,
    device_status,
    document_summary,
    verification_view,
)
from support.pki import Pki, build_pki, minimal_pdf
from support.signed import sign, signed_with_revinfo


@pytest.mark.parametrize(
    ("state", "message", "ready"),
    [
        (
            DeviceState.PCSC_UNAVAILABLE,
            "El servicio de tarjetas inteligentes (pcscd) no está en funcionamiento",
            False,
        ),
        (DeviceState.NO_READER, "Conecta un lector de tarjetas", False),
        (DeviceState.NO_CARD, "Inserta tu DNIe en el lector", False),
        (DeviceState.UNSUPPORTED_CARD, "Tarjeta no compatible", False),
        (DeviceState.DNIE_READY, "DNIe listo", True),
    ],
)
def test_device_status(state: DeviceState, message: str, ready: bool) -> None:
    view = device_status(DeviceStatus(state))
    assert (view.message, view.ready) == (message, ready)
    assert view.icon.endswith("-symbolic")


def test_device_status_before_the_first_sample() -> None:
    assert device_status(None).message == "Buscando lectores de tarjetas…"


def _info(kind: DocumentKind, pages: int | None = None, signatures: int = 0) -> DocumentInfo:
    return DocumentInfo(Path("x"), kind, 10, "00", pages, signatures)


@pytest.mark.parametrize(
    ("info", "summary"),
    [
        (_info(DocumentKind.PDF, 1), "Documento PDF, 1 página, sin firmas"),
        (_info(DocumentKind.PDF, 3, 1), "Documento PDF, 3 páginas, 1 firma"),
        (_info(DocumentKind.PDF, 2, 2), "Documento PDF, 2 páginas, 2 firmas"),
        (
            _info(DocumentKind.OTHER),
            "berigna todavía no puede firmar ni verificar este tipo de archivo.",
        ),
    ],
)
def test_document_summary(info: DocumentInfo, summary: str) -> None:
    assert document_summary(info) == summary


# -- Verification ---------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _verify(pki: Pki, data: bytes) -> VerificationView:
    return verification_view(verify_pdf(data, pki.store, online=False), pki.store)


def test_valid_signature(pki: Pki) -> None:
    view = _verify(pki, signed_with_revinfo(pki))
    assert view.summary == (
        "1 firma válida · El documento no fue modificado después de la última firma."
    )
    assert (view.style, view.retry) == ("success", False)
    [signature] = view.signatures
    assert signature.title == "FIRMANTE"
    assert signature.explanation.startswith("La firma es válida. Firmado por FIRMANTE.")
    details = {d.label: d.value for d in signature.details}
    assert details["Código ETSI EN 319 102-1"] == "TOTAL-PASSED"
    assert details["Formato"] == "PAdES · /ETSI.CAdES.detached"
    assert details["Sello de tiempo de la firma"] == "Ninguno"
    assert signature.signed_revision_length is not None


def test_signature_without_revocation_data_can_be_retried(pki: Pki) -> None:
    signed, _leaf = sign(pki, minimal_pdf())
    view = _verify(pki, signed)
    assert view.summary.startswith("1 firma no se pudo verificar · ")
    assert (view.style, view.retry) == ("warning", True)


def test_altered_document(pki: Pki) -> None:
    signed = bytearray(signed_with_revinfo(pki))
    signed[signed.index(b"Documento de prueba")] = ord("X")
    view = _verify(pki, bytes(signed))
    assert view.summary.startswith("1 firma no es válida · ")
    assert view.style == "error"


def test_several_signatures_and_a_later_change(pki: Pki) -> None:
    first, _ = sign(pki, minimal_pdf(), "PRIMERA")
    both, _ = sign(pki, first, "SEGUNDA")
    view = _verify(pki, both)
    assert view.summary.startswith("2 firmas no se pudieron verificar · ")
    assert [s.title for s in view.signatures] == ["PRIMERA", "SEGUNDA"]
    assert view.summary.endswith("no fue modificado después de la última firma.")


def test_no_signatures(pki: Pki) -> None:
    view = verification_view(PdfVerification((), (), dt.datetime.now(dt.UTC)), pki.store)
    assert view.summary == "Este documento no tiene firmas."
    assert view.style == "warning"


def test_document_timestamp_and_signer_unknown() -> None:
    stamp = TimestampReport(Indication.TOTAL_PASSED, None, None, None, "Sello1")
    signature = PdfSignatureReport(
        "Firma1",
        Indication.TOTAL_FAILED,
        "FORMAT_FAILURE",
        None,
        None,
        "/x",
        False,
        Modifications.OTHER,
        10,
    )
    view = verification_view(
        PdfVerification((signature,), (stamp,), dt.datetime.now(dt.UTC)), TrustStore([])
    )
    assert view.signatures[0].title == "Firmante desconocido"
    assert view.summary.endswith("El documento fue modificado después de la última firma.")
    [timestamp] = view.timestamps
    assert timestamp.title == "Hora ilegible"
    assert {d.label for d in timestamp.details} == {"Código ETSI EN 319 102-1", "Campo de firma"}


def test_timestamps_in_the_details(pki: Pki) -> None:
    when = dt.datetime(2026, 10, 27, 15, 30, tzinfo=dt.UTC)
    stamp = TimestampReport(Indication.TOTAL_PASSED, None, when, pki.ca)
    signature = PdfSignatureReport(
        "Firma1",
        Indication.TOTAL_PASSED,
        None,
        pki.ca,
        None,
        "/x",
        True,
        Modifications.NONE,
        10,
        timestamp=stamp,
    )
    document_stamp = TimestampReport(Indication.TOTAL_PASSED, None, when, pki.ca, "Sello1")
    view = verification_view(PdfVerification((signature,), (document_stamp,), when), pki.store)
    details = {d.label: d.value for d in view.signatures[0].details}
    shown = format_time(when, translations(Language.ES_PE).gettext)  # local time, as on screen
    assert shown.startswith("2026-10-27 a las ")
    assert details["Sello de tiempo de la firma"].startswith(f"{shown} · ")
    assert details["Sello de tiempo de la firma"].endswith(" · TOTAL-PASSED")
    [timestamp] = view.timestamps
    assert timestamp.title == shown
    assert "Autoridad de sellado de tiempo" in {d.label for d in timestamp.details}
