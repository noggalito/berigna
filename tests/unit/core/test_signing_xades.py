# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""XAdES signing orchestration: the same order of security steps as PAdES (RF-006, RF-018,
RF-030 to RF-032, RF-045, P-01) for XML documents."""

import hashlib
from pathlib import Path

import pytest

from berigna.core.errors import (
    CertificateRevokedError,
    LevelNotAvailableError,
    OutputExistsError,
    SigningCancelledError,
    SourceChangedError,
    UnreadableDocumentError,
)
from berigna.core.formats.common import SignatureLevel
from berigna.core.formats.xades import NS, XadesPackaging, parse_xml, signature_element
from berigna.core.signing import SignResult, sign_xades_file, xades_output_path
from berigna.core.token.dnie_v2 import INS_PSO, INS_VERIFY, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import SignerCheck
from support.cards import make_card
from support.pki import Pki, build_pki
from support.prompts import PinPrompt
from support.tsa import make_timestamper

CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><Texto>Documento XML de prueba de berigna</Texto></Declaracion>"
)
SUFFIX = "-firmado"


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@pytest.fixture
def document(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "acta.xml"
    path.write_bytes(CONTENT)
    return path, hashlib.sha256(CONTENT).hexdigest()


def _sign(
    pki: Pki,
    document: tuple[Path, str],
    output: Path,
    *,
    packaging: XadesPackaging = XadesPackaging.ENVELOPED,
    level: SignatureLevel = SignatureLevel.B_B,
    prompt: PinPrompt | None = None,
    revoked: bool = False,
    with_tsa: bool = True,
) -> tuple[SignResult, list[int]]:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, tsa = make_timestamper(pki)
    with DnieV2Token(card) as token:
        result = sign_xades_file(
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


@pytest.mark.parametrize("packaging", list(XadesPackaging))
def test_signs_an_xml_document_without_touching_it(
    pki: Pki, document: tuple[Path, str], packaging: XadesPackaging
) -> None:
    source, _sha = document
    output = xades_output_path(source, packaging, SUFFIX)
    if packaging is XadesPackaging.DETACHED:
        assert output.name == "acta.xml.xsig"
    else:
        assert output.name == "acta-firmado.xml"
    prompt = PinPrompt()
    result, instructions = _sign(pki, document, output, packaging=packaging, prompt=prompt)
    assert result.output == output
    assert result.level is SignatureLevel.B_B
    assert result.sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert source.read_bytes() == CONTENT  # the signed document is never modified
    assert prompt.pins[0].wiped
    assert instructions.count(INS_VERIFY) == 1
    assert instructions.count(INS_PSO) == 1
    signature = signature_element(parse_xml(output.read_bytes()))
    assert signature.find(".//xades:QualifyingProperties", NS) is not None
    if packaging is XadesPackaging.DETACHED:
        [reference] = [
            r
            for r in signature.findall("ds:SignedInfo/ds:Reference", NS)
            if not r.get("URI").startswith("#")  # it names the document it travels with
        ]
        assert reference.get("URI") == "acta.xml"


def test_signs_b_lta_with_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    output = xades_output_path(source, XadesPackaging.ENVELOPED, SUFFIX)
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
        _sign(
            pki,
            document,
            source.with_name("x.xsig"),
            packaging=XadesPackaging.DETACHED,
            prompt=prompt,
            revoked=True,
        )
    assert prompt.shown == []


def test_cancelling_sends_no_pin_and_writes_nothing(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    output = source.with_name("x.xsig")
    with pytest.raises(SigningCancelledError):
        _sign(
            pki, document, output, packaging=XadesPackaging.DETACHED, prompt=PinPrompt(answer=None)
        )
    assert not output.exists()


def test_a_changed_file_is_rejected(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    source.write_bytes(CONTENT + b"<cambio/>")
    prompt = PinPrompt()
    with pytest.raises(SourceChangedError):
        _sign(
            pki,
            document,
            source.with_name("x.xsig"),
            packaging=XadesPackaging.DETACHED,
            prompt=prompt,
        )
    assert prompt.shown == []


def test_a_file_changed_while_the_pin_was_typed_is_not_signed(
    pki: Pki, document: tuple[Path, str]
) -> None:
    source, _sha = document

    class ChangingPrompt(PinPrompt):
        def __call__(self, check: SignerCheck) -> Pin | None:
            source.write_bytes(b"<otro/>")
            return super().__call__(check)

    output = source.with_name("x.xsig")
    with pytest.raises(SourceChangedError):
        _sign(pki, document, output, packaging=XadesPackaging.DETACHED, prompt=ChangingPrompt())
    assert not output.exists()


def test_an_existing_signature_is_never_overwritten(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    output = source.with_name("acta.xml.xsig")
    output.write_bytes(b"firma anterior")
    prompt = PinPrompt()
    with pytest.raises(OutputExistsError):
        _sign(pki, document, output, packaging=XadesPackaging.DETACHED, prompt=prompt)
    assert output.read_bytes() == b"firma anterior"
    assert prompt.shown == []


def test_a_level_above_b_b_needs_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    source, _sha = document
    with pytest.raises(LevelNotAvailableError):
        _sign(
            pki,
            document,
            source.with_name("x-firmado.xml"),
            level=SignatureLevel.B_T,
            with_tsa=False,
        )


def test_a_document_that_is_not_xml_is_rejected_before_the_pin(pki: Pki, tmp_path: Path) -> None:
    source = tmp_path / "carta.docx"
    content = b"PK\x03\x04 un documento que no es XML" * 30
    source.write_bytes(content)
    prompt = PinPrompt()
    with pytest.raises(UnreadableDocumentError):
        _sign(
            pki,
            (source, hashlib.sha256(content).hexdigest()),
            source.with_name("x.xsig"),
            packaging=XadesPackaging.DETACHED,
            prompt=prompt,
        )
    assert prompt.shown == []


def test_xades_output_path_never_reuses_a_name(tmp_path: Path) -> None:
    source = tmp_path / "acta.xml"
    source.write_bytes(b"<acta/>")
    first = xades_output_path(source, XadesPackaging.ENVELOPED, SUFFIX)
    assert first.name == "acta-firmado.xml"
    first.write_bytes(b"")
    second = xades_output_path(source, XadesPackaging.ENVELOPED, SUFFIX)
    assert second.name == "acta-firmado-2.xml"
    second.write_bytes(b"")
    assert xades_output_path(source, XadesPackaging.ENVELOPING, SUFFIX).name == "acta-firmado-3.xml"
    first_detached = xades_output_path(source, XadesPackaging.DETACHED, SUFFIX)
    assert first_detached.name == "acta.xml.xsig"
    first_detached.write_bytes(b"")
    assert xades_output_path(source, XadesPackaging.DETACHED, SUFFIX).name == "acta-2.xml.xsig"
    elsewhere = tmp_path / "firmas"
    elsewhere.mkdir()
    assert xades_output_path(source, XadesPackaging.DETACHED, SUFFIX, elsewhere) == (
        elsewhere / "acta.xml.xsig"
    )
