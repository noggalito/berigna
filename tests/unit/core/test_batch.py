# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Batch signing with one PIN (CU-04; RF-040 to RF-043)."""

import csv
import hashlib
import io
from pathlib import Path

import pytest

from berigna.core.batch import BatchItem, Outcome, batch_outputs, sign_pdf_batch
from berigna.core.errors import CardRemovedError, SigningCancelledError
from berigna.core.i18n import Language
from berigna.core.report.batch_report import batch_csv
from berigna.core.signing import SigningJob
from berigna.core.token.dnie_v2 import INS_PSO, INS_VERIFY, DnieV2Token
from berigna.core.validation import Indication, verify_pdf
from support.cards import make_card
from support.pki import Pki, build_pki, minimal_pdf
from support.prompts import PinPrompt


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _jobs(tmp_path: Path, count: int) -> list[SigningJob]:
    jobs = []
    for number in range(1, count + 1):
        path = tmp_path / f"documento-{number}.pdf"
        data = minimal_pdf(f"Documento {number}")
        path.write_bytes(data)
        output = path.with_name(f"documento-{number}-firmado.pdf")
        jobs.append(SigningJob(path, output, hashlib.sha256(data).hexdigest()))
    return jobs


def _sign(
    pki: Pki, jobs: list[SigningJob], **kwargs: object
) -> tuple[list[BatchItem], object, object]:
    card, leaf = make_card(pki, "FIRMANTE LOTE")
    prompt = kwargs.pop("prompt", PinPrompt())
    with DnieV2Token(card) as token:
        items = sign_pdf_batch(
            jobs,
            token=token,
            store=pki.store,
            ask_pin=prompt,  # type: ignore[arg-type]
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],
            **kwargs,  # type: ignore[arg-type]
        )
    return items, card, leaf


def test_one_pin_for_the_whole_batch(pki: Pki, tmp_path: Path) -> None:
    """RF-040: the PIN is asked and sent once; every file is signed and valid."""
    jobs = _jobs(tmp_path, 5)
    prompt = PinPrompt()
    seen: list[tuple[int, int]] = []
    items, card, leaf = _sign(
        pki, jobs, prompt=prompt, progress=lambda d, t, _i: seen.append((d, t))
    )
    assert [item.outcome for item in items] == [Outcome.SIGNED] * 5
    assert len(prompt.shown) == 1
    assert card.instructions().count(INS_VERIFY) == 1  # type: ignore[attr-defined]
    assert card.instructions().count(INS_PSO) == 5  # type: ignore[attr-defined]
    assert seen == [(n, 5) for n in range(1, 6)]
    for job in jobs:
        report = verify_pdf(
            job.output.read_bytes(),
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],  # type: ignore[arg-type]
            crls=[pki.arl()],
        )
        assert report.signatures[0].indication is Indication.TOTAL_PASSED


def test_a_bad_file_does_not_stop_the_others(pki: Pki, tmp_path: Path) -> None:
    """RF-043: files that fail the checks are reported before the PIN; the rest are signed."""
    jobs = _jobs(tmp_path, 4)
    jobs[1].source.write_bytes(b"cambiado")  # changed after the user confirmed the list
    jobs[2].output.write_bytes(b"ya existe")  # never overwritten (RF-045)
    items, _card, _leaf = _sign(pki, jobs)
    assert [item.outcome for item in items] == [
        Outcome.SIGNED,
        Outcome.FAILED,
        Outcome.FAILED,
        Outcome.SIGNED,
    ]
    assert [item.code for item in items] == [None, "ERR-301", "ERR-302", None]
    assert jobs[2].output.read_bytes() == b"ya existe"


def test_cancel_between_files(pki: Pki, tmp_path: Path) -> None:
    jobs = _jobs(tmp_path, 4)
    done: list[BatchItem] = []
    items, _card, _leaf = _sign(
        pki,
        jobs,
        progress=lambda _d, _t, item: done.append(item),
        cancelled=lambda: len(done) >= 2,
    )
    assert [item.outcome for item in items] == [Outcome.SIGNED] * 2 + [Outcome.SKIPPED] * 2
    assert {item.code for item in items[2:]} == {"ERR-309"}
    assert not jobs[3].output.exists()


def test_a_removed_card_stops_the_batch(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The card is gone: the file being signed failed, the following ones were not tried."""
    import berigna.core.batch as batch

    jobs = _jobs(tmp_path, 3)
    real = batch.sign_checked
    calls = []

    def flaky(job: SigningJob, **kwargs: object) -> object:
        calls.append(job)
        if len(calls) == 2:
            raise CardRemovedError("card removed")
        return real(job, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(batch, "sign_checked", flaky)
    items, _card, _leaf = _sign(pki, jobs)
    assert [item.outcome for item in items] == [Outcome.SIGNED, Outcome.FAILED, Outcome.SKIPPED]
    assert [item.code for item in items] == [None, "ERR-105", "ERR-105"]
    assert len(calls) == 2


def test_nothing_to_sign_asks_no_pin(pki: Pki, tmp_path: Path) -> None:
    jobs = _jobs(tmp_path, 2)
    for job in jobs:
        job.output.write_bytes(b"ya existe")
    prompt = PinPrompt()
    items, card, _leaf = _sign(pki, jobs, prompt=prompt)
    assert {item.outcome for item in items} == {Outcome.FAILED}
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()  # type: ignore[attr-defined]


def test_cancelling_the_pin_signs_nothing(pki: Pki, tmp_path: Path) -> None:
    jobs = _jobs(tmp_path, 2)
    with pytest.raises(SigningCancelledError):
        _sign(pki, jobs, prompt=PinPrompt(answer=None))
    assert not any(job.output.exists() for job in jobs)


def test_outputs_never_collide(tmp_path: Path) -> None:
    """Two "contrato.pdf" into one output folder; an existing numbered name is skipped too."""
    out = tmp_path / "firmados"
    out.mkdir()
    (out / "contrato-firmado.pdf").write_bytes(b"ya existe")
    sources = [tmp_path / "a" / "contrato.pdf", tmp_path / "b" / "contrato.pdf"]
    assert batch_outputs(sources, "-firmado", out) == [
        out / "contrato-firmado-2.pdf",
        out / "contrato-firmado-3.pdf",
    ]
    assert batch_outputs([tmp_path / "a" / "acta.pdf"], "-firmado") == [
        tmp_path / "a" / "acta-firmado.pdf"
    ]


def test_csv_report(pki: Pki, tmp_path: Path) -> None:
    """RF-042: one row per file, with the result and why a file was not signed."""
    jobs = _jobs(tmp_path, 2)
    jobs[1].output.write_bytes(b"ya existe")
    items, _card, _leaf = _sign(pki, jobs)
    rows = list(csv.reader(io.StringIO(batch_csv(items))))
    assert rows[0] == [
        "Archivo",
        "Carpeta",
        "Resultado",
        "Archivo firmado",
        "Nivel",
        "SHA-256 del archivo firmado",
        "Código",
        "Explicación",
    ]
    signed, failed = rows[1:]
    assert signed[:5] == [
        "documento-1.pdf",
        str(tmp_path),
        "Firmado",
        "documento-1-firmado.pdf",
        "B-B",
    ]
    assert signed[5] == hashlib.sha256(jobs[0].output.read_bytes()).hexdigest()
    assert failed[2] == "No firmado"
    assert failed[6] == "ERR-302"
    assert failed[7].startswith("Ya existe un archivo")
    quechua = list(csv.reader(io.StringIO(batch_csv(items, Language.QUZ_PE))))
    assert quechua[2][7] == "Ñam kan chay sutiyuq archivo. Huk sutita akllay."


def test_a_file_failing_while_signing_does_not_stop_the_others(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RF-043: a file changed between the checks and its turn fails alone (ERR-301)."""
    import berigna.core.batch as batch

    jobs = _jobs(tmp_path, 3)
    real = batch.sign_checked

    def changing(job: SigningJob, **kwargs: object) -> object:
        if job is jobs[1]:
            job.source.write_bytes(b"cambiado mientras se firmaba el lote")
        return real(job, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(batch, "sign_checked", changing)
    items, _card, _leaf = _sign(pki, jobs)
    assert [item.outcome for item in items] == [Outcome.SIGNED, Outcome.FAILED, Outcome.SIGNED]
    assert items[1].code == "ERR-301"
