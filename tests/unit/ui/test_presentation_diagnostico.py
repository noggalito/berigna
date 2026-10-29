# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Words of the diagnosis (CU-07, RF-007)."""

import datetime as dt

import pytest

from berigna.core.diagnostics import Result, Status, Step
from berigna.ui.presentation import diagnosis_report, diagnosis_text

EXPIRES = dt.datetime(2027, 1, 21, 17, 37, tzinfo=dt.UTC).isoformat()
SIGNER = {"signer": "QUISPE MAMANI ROSA FIR ****4321 hard", "expires": EXPIRES}


@pytest.mark.parametrize(
    ("result", "start"),
    [
        (Result(Step.PCSC, Status.OK), "El servicio está activo"),
        (Result(Step.PCSC, Status.ERROR), "El servicio no está activo. Instálalo"),
        (Result(Step.READER, Status.OK, facts={"readers": "innovatech"}), "Conectado: innovatech"),
        (Result(Step.READER, Status.ERROR), "No hay ningún lector"),
        (Result(Step.READER, Status.SKIPPED), "No se comprobó porque falló"),
        (Result(Step.CARD, Status.OK, facts={"reader": "innovatech"}), "Hay un DNIe en innovatech"),
        (Result(Step.CARD, Status.ERROR, facts={"atr": "3B 00"}), "La tarjeta del lector no es"),
        (Result(Step.CARD, Status.ERROR), "No hay ninguna tarjeta"),
        (Result(Step.CERTIFICATE, Status.ERROR, "ERR-105"), "Se retiró el DNIe"),
        (
            Result(Step.CERTIFICATE, Status.OK, facts={**SIGNER, "days": "90"}),
            "QUISPE MAMANI ROSA FIR ****4321 hard, vigente hasta el 2027-01-21",
        ),
        (
            Result(Step.CERTIFICATE, Status.WARNING, facts={**SIGNER, "days": "1"}),
            "QUISPE MAMANI ROSA FIR ****4321 hard: el certificado vence el 2027-01-21, "
            "dentro de 1 día",
        ),
        (
            Result(Step.CERTIFICATE, Status.ERROR, "ERR-211", {**SIGNER, "days": "0"}),
            "QUISPE MAMANI ROSA FIR ****4321 hard: el certificado venció",
        ),
        (Result(Step.VALIDATION, Status.OK), "Tu certificado es de confianza"),
        (Result(Step.VALIDATION, Status.WARNING, facts={"note": "offline"}), "No se comprobó la"),
        (
            Result(Step.VALIDATION, Status.WARNING, facts={"note": "unavailable"}),
            "No se pudo consultar",
        ),
        (Result(Step.VALIDATION, Status.ERROR, "ERR-212"), "Tu certificado fue revocado"),
        (Result(Step.TSA, Status.OK), "La autoridad de sellado de tiempo respondió"),
        (
            Result(Step.TSA, Status.SKIPPED, facts={"configured": "False"}),
            "No hay ninguna autoridad",
        ),
        (Result(Step.TSA, Status.SKIPPED, facts={"configured": "True"}), "No se comprobó: berigna"),
        (
            Result(Step.TSA, Status.ERROR, "ERR-305"),
            "La autoridad de sellado de tiempo no respondió",
        ),
    ],
)
def test_texts(result: Result, start: str) -> None:
    assert diagnosis_text(result).startswith(start)


def test_report_masks_numbers() -> None:
    results = [
        Result(Step.PCSC, Status.OK),
        Result(Step.READER, Status.OK, facts={"readers": "Lector 12345678"}),
    ]
    report = diagnosis_report(results, "1.0.0", "Debian GNU/Linux 13 (trixie)")
    lines = report.splitlines()
    assert lines[0].startswith("Diagnóstico de berigna 1.0.0, ")
    assert lines[1] == "Debian GNU/Linux 13 (trixie)"
    assert lines[3] == "[✓] Servicio de tarjetas inteligentes (pcscd): El servicio está activo."
    assert "12345678" not in report
