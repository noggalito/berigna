# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Signing orchestration: order of the security steps (RF-006, RF-018, RF-045, P-01)."""

import hashlib
import io
from pathlib import Path
from typing import Any

import pytest
from pyhanko.pdf_utils.reader import PdfFileReader

from berigna.core.errors import (
    CertificateRevokedError,
    LevelNotAvailableError,
    OutputExistsError,
    PdfFormatError,
    SigningCancelledError,
    SourceChangedError,
    TsaError,
)
from berigna.core.formats.pades import SignatureLevel
from berigna.core.signing import sign_pdf_file, write_atomically
from berigna.core.token.dnie_v2 import INS_PSO, INS_VERIFY, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import Indication, SignerCheck, verify_pdf
from support.cards import make_card
from support.pki import Pki, build_pki, minimal_pdf
from support.tsa import make_timestamper


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@pytest.fixture
def document(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "contrato.pdf"
    data = minimal_pdf()
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


class PinPrompt:
    """Stands in for the UI dialog; records what it was shown."""

    def __init__(self, answer: str | None = "123456") -> None:
        self.answer = answer
        self.shown: list[SignerCheck] = []
        self.pins: list[Pin] = []

    def __call__(self, check: SignerCheck) -> Pin | None:
        self.shown.append(check)
        if self.answer is None:
            return None
        pin = Pin(self.answer)
        self.pins.append(pin)
        return pin


def test_signs_and_writes_a_new_file(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    output = source.with_name("contrato-firmado.pdf")
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],
            crls=[pki.arl()],
        )
    assert result.output == output
    assert result.level is SignatureLevel.B_B
    assert result.level_note is None
    assert result.revocation_checked
    assert result.sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert len(PdfFileReader(io.BytesIO(output.read_bytes())).embedded_signatures) == 1
    assert source.read_bytes() == minimal_pdf()  # the original is never modified
    assert prompt.pins[0].wiped
    assert sorted(p.name for p in source.parent.iterdir()) == [
        "contrato-firmado.pdf",
        "contrato.pdf",
    ]


def test_without_revocation_data_the_result_says_so(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, _ = make_card(pki, "FIRMANTE SIN RED")
    prompt = PinPrompt()
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            source.with_name("f.pdf"),
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert not result.revocation_checked
    assert prompt.shown[0].only_basic_level  # the UI can warn before asking the PIN


def test_revoked_certificate_is_rejected_before_asking_the_pin(
    pki: Pki, document: tuple[Path, str]
) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE REVOCADO")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(CertificateRevokedError):
        sign_pdf_file(
            source,
            source.with_name("f.pdf"),
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
            ocsp_responses=[pki.ocsp(leaf, revoked=True)],
            crls=[pki.arl()],
        )
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()


def test_cancelling_sends_no_pin(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, _ = make_card(pki, "FIRMANTE")
    output = source.with_name("f.pdf")
    with DnieV2Token(card) as token, pytest.raises(SigningCancelledError):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=PinPrompt(answer=None),
            online=False,
        )
    assert INS_VERIFY not in card.instructions()
    assert not output.exists()


def test_damaged_pdf_is_rejected_before_asking_the_pin(pki: Pki, tmp_path: Path) -> None:
    """D-2: a file that cannot be signed must not cost the user a PIN entry."""
    source = tmp_path / "danado.pdf"
    data = b"%PDF-1.7\nesto no es un PDF completo\n"
    source.write_bytes(data)
    card, _ = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(PdfFormatError):
        sign_pdf_file(
            source,
            tmp_path / "f.pdf",
            expected_sha256=hashlib.sha256(data).hexdigest(),
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()


def test_file_changed_before_starting(pki: Pki, document: tuple[Path, str]) -> None:
    source, _ = document
    card, _ = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(SourceChangedError):
        sign_pdf_file(
            source,
            source.with_name("f.pdf"),
            expected_sha256="0" * 64,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert prompt.shown == []
    assert card.headers == []


def test_file_changed_while_the_pin_was_being_typed(pki: Pki, document: tuple[Path, str]) -> None:
    """AM-02 (TOCTOU): a change during the PIN dialog aborts before the chip signs."""
    source, sha = document
    card, _ = make_card(pki, "FIRMANTE")
    output = source.with_name("f.pdf")

    def tampering_prompt(check: SignerCheck) -> Pin:
        source.write_bytes(minimal_pdf("Contenido cambiado"))
        return Pin("123456")

    with DnieV2Token(card) as token, pytest.raises(SourceChangedError):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=tampering_prompt,
            online=False,
        )
    assert INS_PSO not in card.instructions()
    assert not output.exists()


def test_existing_output_is_never_overwritten(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    output = source.with_name("ya-existe.pdf")
    output.write_bytes(b"contenido previo")
    card, _ = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(OutputExistsError):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert output.read_bytes() == b"contenido previo"
    assert prompt.shown == []


def test_atomic_write_never_replaces_and_leaves_no_temporary_files(tmp_path: Path) -> None:
    target = tmp_path / "salida.pdf"
    write_atomically(target, b"uno")
    with pytest.raises(OutputExistsError):
        write_atomically(target, b"dos")
    assert target.read_bytes() == b"uno"
    assert [p.name for p in tmp_path.iterdir()] == ["salida.pdf"]


def test_atomic_write_replaces_only_when_asked(tmp_path: Path) -> None:
    target = tmp_path / "informe.pdf"
    target.write_bytes(b"anterior")
    write_atomically(target, b"nuevo", replace=True)
    assert target.read_bytes() == b"nuevo"
    assert [p.name for p in tmp_path.iterdir()] == ["informe.pdf"]


def test_atomic_write_detects_a_file_created_meanwhile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "carrera.pdf"
    real_link = __import__("os").link

    def racing_link(src: str, dst: Path) -> None:
        Path(dst).write_bytes(b"otro proceso")
        real_link(src, dst)

    monkeypatch.setattr("berigna.core.signing.os.link", racing_link)
    with pytest.raises(OutputExistsError):
        write_atomically(target, b"mio")
    assert target.read_bytes() == b"otro proceso"
    assert [p.name for p in tmp_path.iterdir()] == ["carrera.pdf"]


# -- Levels above B-B (RF-010, RF-062) ----------------------------------------------------------


def test_signs_b_lt_with_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE B-LT")
    stamper, tsa_cert = make_timestamper(pki)
    output = source.with_name("b-lt.pdf")
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=PinPrompt(),
            level=SignatureLevel.B_LT,
            timestamper=stamper,
            online=False,
            ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa_cert)],
            crls=[pki.arl()],
        )
    assert result.level is SignatureLevel.B_LT
    assert result.level_note is None
    [report] = verify_pdf(output.read_bytes(), pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_PASSED


def _refused_before_the_pin(
    pki: Pki,
    document: tuple[Path, str],
    error: type[Exception],
    *,
    timestamper: Any = None,
    revinfo: bool = False,
) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    output = source.with_name("f.pdf")
    with DnieV2Token(card) as token, pytest.raises(error):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            level=SignatureLevel.B_T,
            timestamper=timestamper,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)] if revinfo else [],
            crls=[pki.arl()] if revinfo else [],
        )
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()
    assert not output.exists()


def test_level_above_b_b_needs_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    _refused_before_the_pin(pki, document, LevelNotAvailableError, revinfo=True)


def test_level_above_b_b_needs_revocation_checked(pki: Pki, document: tuple[Path, str]) -> None:
    """RF-006: without revocation data only B-B may be offered."""
    stamper, _ = make_timestamper(pki)
    _refused_before_the_pin(pki, document, LevelNotAvailableError, timestamper=stamper)


def test_unreachable_tsa_is_detected_before_the_pin(pki: Pki, document: tuple[Path, str]) -> None:
    stamper, _ = make_timestamper(pki, fail_on=frozenset({1}))
    _refused_before_the_pin(pki, document, TsaError, timestamper=stamper, revinfo=True)
