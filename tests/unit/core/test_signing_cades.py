# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""CAdES signing orchestration: the same order of security steps as PAdES (RF-006, RF-018,
RF-020, RF-021, RF-045, P-01) for any file."""

import asyncio
import hashlib
from pathlib import Path

import pytest
from asn1crypto import cms
from pyhanko.sign.validation import async_validate_detached_cms
from pyhanko_certvalidator import ValidationContext

from berigna.core.certs import to_asn1
from berigna.core.errors import (
    CertificateRevokedError,
    LevelNotAvailableError,
    OutputExistsError,
    SigningCancelledError,
    SourceChangedError,
)
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.common import SignatureLevel
from berigna.core.signing import SignResult, cades_output_path, sign_cades_file
from berigna.core.token.dnie_v2 import INS_PSO, INS_VERIFY, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import SignerCheck
from support.cards import make_card
from support.pki import Pki, build_pki
from support.prompts import PinPrompt
from support.tsa import make_timestamper

CONTENT = b"PK\x03\x04 un documento que no es PDF, por ejemplo un .docx" * 30


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@pytest.fixture
def document(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "informe.docx"
    path.write_bytes(CONTENT)
    return path, hashlib.sha256(CONTENT).hexdigest()


def _sign(
    pki: Pki,
    document: tuple[Path, str],
    output: Path,
    *,
    packaging: CadesPackaging = CadesPackaging.DETACHED,
    level: SignatureLevel = SignatureLevel.B_B,
    prompt: PinPrompt | None = None,
    revoked: bool = False,
    with_tsa: bool = True,
) -> tuple[SignResult, list[int]]:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, tsa = make_timestamper(pki)
    with DnieV2Token(card) as token:
        result = sign_cades_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt or PinPrompt(),
            packaging=packaging,
            level=level,
            timestamper=stamper if with_tsa else None,
            online=False,
            ocsp_responses=[pki.ocsp(leaf, revoked=revoked), pki.ocsp(tsa)],
            crls=[pki.arl()],
        )
    return result, card.instructions()


@pytest.mark.parametrize("packaging", list(CadesPackaging))
def test_signs_any_file_without_touching_it(
    pki: Pki, document: tuple[Path, str], packaging: CadesPackaging
) -> None:
    source, _sha = document
    output = cades_output_path(source, packaging)
    assert output.name == f"informe.docx.{packaging.value}"
    prompt = PinPrompt()
    result, instructions = _sign(pki, document, output, packaging=packaging, prompt=prompt)
    assert result.output == output
    assert result.level is SignatureLevel.B_B
    assert result.sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert source.read_bytes() == CONTENT  # the signed file is never modified
    assert prompt.pins[0].wiped
    assert instructions.count(INS_VERIFY) == 1
    assert instructions.count(INS_PSO) == 1
    signed_data = cms.ContentInfo.load(output.read_bytes())["content"]
    if packaging is CadesPackaging.DETACHED:
        context = ValidationContext(trust_roots=[to_asn1(pki.root)], other_certs=[to_asn1(pki.ca)])
        status = asyncio.run(async_validate_detached_cms(CONTENT, signed_data, context))
        assert status.intact
        assert status.valid
    else:
        assert signed_data["encap_content_info"]["content"].native == CONTENT


def test_signs_b_lta_with_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    output = cades_output_path(source, CadesPackaging.DETACHED)
    result, instructions = _sign(pki, document, output, level=SignatureLevel.B_LTA)
    assert result.level is SignatureLevel.B_LTA
    assert result.level_note is None
    assert instructions.count(INS_PSO) == 1


def test_a_revoked_certificate_is_rejected_before_the_pin(
    pki: Pki, document: tuple[Path, str]
) -> None:
    source, _sha = document
    prompt = PinPrompt()
    with pytest.raises(CertificateRevokedError):
        _sign(pki, document, source.with_name("x.p7s"), prompt=prompt, revoked=True)
    assert prompt.shown == []


def test_cancelling_sends_no_pin_and_writes_nothing(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    output = source.with_name("x.p7s")
    with pytest.raises(SigningCancelledError):
        _sign(pki, document, output, prompt=PinPrompt(answer=None))
    assert not output.exists()


def test_a_changed_file_is_rejected(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    source.write_bytes(CONTENT + b"modificado")
    prompt = PinPrompt()
    with pytest.raises(SourceChangedError):
        _sign(pki, document, source.with_name("x.p7s"), prompt=prompt)
    assert prompt.shown == []


def test_a_file_changed_while_the_pin_was_typed_is_not_signed(
    pki: Pki, document: tuple[Path, str]
) -> None:
    source, _sha = document

    class ChangingPrompt(PinPrompt):
        def __call__(self, check: SignerCheck) -> Pin | None:
            source.write_bytes(b"otro contenido")
            return super().__call__(check)

    output = source.with_name("x.p7s")
    with pytest.raises(SourceChangedError):
        _sign(pki, document, output, prompt=ChangingPrompt())
    assert not output.exists()


def test_an_existing_signature_is_never_overwritten(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    output = source.with_name("informe.docx.p7s")
    output.write_bytes(b"firma anterior")
    prompt = PinPrompt()
    with pytest.raises(OutputExistsError):
        _sign(pki, document, output, prompt=prompt)
    assert output.read_bytes() == b"firma anterior"
    assert prompt.shown == []


def test_a_level_above_b_b_needs_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    with pytest.raises(LevelNotAvailableError):
        _sign(pki, document, source.with_name("x.p7s"), level=SignatureLevel.B_T, with_tsa=False)


def test_cades_output_path_never_reuses_a_name(tmp_path: Path) -> None:
    source = tmp_path / "acta.xml"
    source.write_bytes(b"<acta/>")
    first = cades_output_path(source, CadesPackaging.ENVELOPING)
    assert first.name == "acta.xml.p7m"
    first.write_bytes(b"")
    second = cades_output_path(source, CadesPackaging.ENVELOPING)
    assert second.name == "acta-2.xml.p7m"  # removing .p7m still gives an .xml
    second.write_bytes(b"")
    assert cades_output_path(source, CadesPackaging.ENVELOPING).name == "acta-3.xml.p7m"
    assert cades_output_path(source, CadesPackaging.DETACHED).name == "acta.xml.p7s"
    elsewhere = tmp_path / "firmas"
    elsewhere.mkdir()
    assert cades_output_path(source, CadesPackaging.DETACHED, elsewhere) == (
        elsewhere / "acta.xml.p7s"
    )
