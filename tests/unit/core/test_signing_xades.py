# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""XAdES signing orchestration: the same order of security steps as PAdES (RF-006, RF-018,
RF-030 to RF-032, RF-045, P-01) for XML documents."""

import hashlib
from pathlib import Path

import pytest

from berigna.core.errors import (
    AlreadySignedError,
    CertificateRevokedError,
    LevelNotAvailableError,
    OutputExistsError,
    SigningCancelledError,
    SourceChangedError,
    XmlDtdError,
    XmlFormatError,
    XmlPrologueError,
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
    """With a signing code (ERR-30x), as a PDF that cannot be signed is, not the
    verification code of ERR-401 (review of 2026-11-01)."""
    source = tmp_path / "carta.docx"
    content = b"PK\x03\x04 un documento que no es XML" * 30
    source.write_bytes(content)
    prompt = PinPrompt()
    with pytest.raises(XmlFormatError):
        _sign(
            pki,
            (source, hashlib.sha256(content).hexdigest()),
            source.with_name("x.xsig"),
            packaging=XadesPackaging.DETACHED,
            prompt=prompt,
        )
    assert prompt.shown == []


def test_a_document_with_a_dtd_is_rejected_before_the_pin(pki: Pki, tmp_path: Path) -> None:
    """A DTD can hide entity attacks: refused with its own message, before the PIN (review
    of 2026-11-01)."""
    source = tmp_path / "con-dtd.xml"
    content = b'<?xml version="1.0"?><!DOCTYPE Acta [<!ENTITY x "y">]><Acta>&x;</Acta>'
    source.write_bytes(content)
    prompt = PinPrompt()
    with pytest.raises(XmlDtdError):
        _sign(
            pki,
            (source, hashlib.sha256(content).hexdigest()),
            source.with_name("x.xsig"),
            packaging=XadesPackaging.DETACHED,
            prompt=prompt,
        )
    assert prompt.shown == []


def test_a_document_with_instructions_outside_the_root_is_rejected_before_the_pin(
    pki: Pki, tmp_path: Path
) -> None:
    """The detached digest covers the root element alone and a validator digests the
    instructions outside it: refused before the PIN, with the enveloping form left to
    choose (review of 2026-11-01)."""
    source = tmp_path / "con-estilo.xml"
    content = (
        b'<?xml version="1.0"?>'
        b'<?xml-stylesheet type="text/xsl" href="estilo.xsl"?>'
        b"<Acta>sesion de prueba</Acta>"
    )
    source.write_bytes(content)
    prompt = PinPrompt()
    with pytest.raises(XmlPrologueError):
        _sign(
            pki,
            (source, hashlib.sha256(content).hexdigest()),
            source.with_name("x.xsig"),
            packaging=XadesPackaging.DETACHED,
            prompt=prompt,
        )
    assert prompt.shown == []


def test_an_already_signed_document_refuses_the_enveloped_form_before_the_pin(
    pki: Pki, document: tuple[Path, str]
) -> None:
    """An enveloped signature over a signed document would break the signature it already
    has: refused before the PIN costs nothing, and the detached form still signs it (review
    of 2026-11-01)."""
    source, _sha = document
    output = xades_output_path(source, XadesPackaging.ENVELOPED, SUFFIX)
    _sign(pki, document, output)  # the document now carries a signature
    signed = (output, hashlib.sha256(output.read_bytes()).hexdigest())
    prompt = PinPrompt()
    with pytest.raises(AlreadySignedError):
        _sign(pki, signed, output.with_name("acta-firmado-2.xml"), prompt=prompt)
    assert prompt.shown == []  # refused before the PIN
    detached, _instructions = _sign(
        pki, signed, output.with_suffix(".xml.xsig"), packaging=XadesPackaging.DETACHED
    )
    assert detached.level is SignatureLevel.B_B
    assert hashlib.sha256(output.read_bytes()).hexdigest() == signed[1]  # untouched


def test_the_detached_signature_quotes_the_uri_of_the_document(pki: Pki, tmp_path: Path) -> None:
    """A name with spaces and tildes is percent-encoded in the URI, as RFC 3986 says a
    valid URI must be, so that a validator can find the document (review of 2026-11-01)."""
    content = (
        '<?xml version="1.0" encoding="UTF-8"?><Acta>sesión de prueba áéíóúñ</Acta>'
    ).encode()
    source = tmp_path / "acta de sesión.xml"
    source.write_bytes(content)
    output = tmp_path / "acta de sesión.xml.xsig"
    _sign(
        pki,
        (source, hashlib.sha256(content).hexdigest()),
        output,
        packaging=XadesPackaging.DETACHED,
    )
    signature = signature_element(parse_xml(output.read_bytes()))
    [reference] = [
        r
        for r in signature.findall("ds:SignedInfo/ds:Reference", NS)
        if not r.get("URI").startswith("#")  # it names the document it travels with
    ]
    assert reference.get("URI") == "acta%20de%20sesi%C3%B3n.xml"


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
