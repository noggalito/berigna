# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The XAdES digests and signature value, checked by xmlsec1: a verifier that shares no
code with berigna (review of 2026-11-01). test_xades.py recomputes the octets itself; this
one hands the signature to another program and expects its OK, whatever the packaging and
the comments in the document.

Needs the xmlsec1 of Debian:  apt install xmlsec1
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from berigna.core.formats.common import SignatureLevel
from berigna.core.formats.xades import XadesPackaging, sign_xades
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import signing_validation_context
from support.cards import make_card
from support.pki import Pki, build_pki
from support.tsa import make_timestamper

# Comments inside: the case in which the digests must exclude them, as XMLDSig says
CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><!-- nota de dentro --><Titular>PRUEBA FIRMANTE</Titular>"
    b"<Texto>Documento XML de prueba de berigna</Texto><!-- otra nota --></Declaracion>"
)


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@pytest.fixture(scope="module")
def anchors(pki: Pki, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The test PKI as xmlsec1 wants it: the CA and the root close the chain of the leaf,
    which is the only certificate the signature embeds."""
    path = tmp_path_factory.mktemp("xmlsec1") / "anclas.pem"
    path.write_bytes(
        pki.ca.public_bytes(serialization.Encoding.PEM)
        + pki.root.public_bytes(serialization.Encoding.PEM)
    )
    return path


def _xmlsec1() -> str:
    binary = shutil.which("xmlsec1")
    if binary is None:
        pytest.fail("xmlsec1 is needed: apt install xmlsec1")
    return binary


def _verify(binary: str, anchors: Path, folder: Path, name: str) -> None:
    result = subprocess.run(  # noqa: S603 - fixed program, arguments from the test
        [binary, "--verify", "--trusted-pem", str(anchors), name],
        cwd=folder,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _sign(
    pki: Pki,
    packaging: XadesPackaging,
    level: SignatureLevel = SignatureLevel.B_B,
) -> bytes:
    card, leaf = make_card(pki, f"FIRMANTE XMLSEC1 {packaging.value}")
    stamper, tsa_cert = make_timestamper(pki)
    context = signing_validation_context(
        pki.store,
        online=False,
        ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa_cert)],
        crls=[pki.arl()],
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        return sign_xades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            packaging=packaging,
            level=level,
            reference_uri="datos.xml" if packaging is XadesPackaging.DETACHED else None,
            timestamper=None if level is SignatureLevel.B_B else stamper,
            validation_context=context,
        ).data


@pytest.mark.parametrize("packaging", list(XadesPackaging))
def test_xmlsec1_verifies_the_signature_whatever_the_packaging(
    pki: Pki, anchors: Path, tmp_path: Path, packaging: XadesPackaging
) -> None:
    tmp_path.joinpath("datos.xml").write_bytes(CONTENT)  # the detached signature names it
    tmp_path.joinpath("firma.xml").write_bytes(_sign(pki, packaging))
    _verify(_xmlsec1(), anchors, tmp_path, "firma.xml")


def test_xmlsec1_verifies_a_b_lta_whatever_was_added_after_signing(
    pki: Pki, anchors: Path, tmp_path: Path
) -> None:
    """The unsigned properties of B-T, B-LT and B-LTA do not touch what was signed."""
    tmp_path.joinpath("firma.xml").write_bytes(
        _sign(pki, XadesPackaging.ENVELOPED, SignatureLevel.B_LTA)
    )
    _verify(_xmlsec1(), anchors, tmp_path, "firma.xml")


def test_xmlsec1_rejects_a_document_changed_after_signing(
    pki: Pki, anchors: Path, tmp_path: Path
) -> None:
    """That the OK above means something: with the content changed, xmlsec1 refuses."""
    tmp_path.joinpath("firma.xml").write_bytes(
        _sign(pki, XadesPackaging.ENVELOPED).replace(b"berigna", b"otro programa")
    )
    result = subprocess.run(  # noqa: S603 - fixed program, arguments from the test
        [_xmlsec1(), "--verify", "--trusted-pem", str(anchors), "firma.xml"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
