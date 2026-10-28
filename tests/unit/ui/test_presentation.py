# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
from pathlib import Path

import pytest

from berigna.core.documents import DocumentInfo, DocumentKind
from berigna.core.token.monitor import DeviceState, DeviceStatus
from berigna.ui.presentation import device_status, document_summary


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
