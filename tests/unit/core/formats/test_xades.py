# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""XAdES through the DNIe v2 driver (simulator) and a test TSA: PR-XAD-01 to PR-XAD-12,
RF-030 to RF-033. The checks recomputed here (digest of the references, imprint of both
time-stamps) do not use the module's own helpers: the octets follow EN 319 132-1 §5.4.2,
with C14N 1.0 without comments, as XMLDSig digests ``URI=""`` and ``#id`` references
(review of 2026-11-01). The external validation with DSS 6.2 is tests/interop/matriz_xades.py."""

import asyncio
import base64
import copy
import hashlib
from dataclasses import dataclass
from typing import Any

import pytest
from asn1crypto import cms, ocsp, tsp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree
from pyhanko_certvalidator.policy_decl import RevocationCheckingPolicy, RevocationCheckingRule

from berigna.core.certs import to_asn1
from berigna.core.errors import (
    AlreadySignedError,
    TsaError,
    XmlDtdError,
    XmlFormatError,
    XmlPrologueError,
)
from berigna.core.formats.common import SignatureLevel
from berigna.core.formats.xades import (
    DS,
    ENVELOPED,
    EXC_C14N,
    NS,
    XADES,
    XADES141,
    XadesPackaging,
    XadesResult,
    _add_archive_timestamp,
    _add_validation_data,
    _TokenKey,
    _unsigned_properties,
    parse_xml,
    sign_xades,
    signature_element,
)
from berigna.core.net.tsa import token_certificates
from berigna.core.token.base import HashAlgorithmName
from berigna.core.token.dnie_v2 import INS_PSO, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import signing_validation_context
from support.cards import make_card
from support.pki import Pki, build_pki
from support.tsa import FlakyTimeStamper, make_timestamper, unknown_timestamper

CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><Titular>PRUEBA FIRMANTE</Titular>"
    b"<Texto>Documento XML de prueba de berigna</Texto></Declaracion>"
)
# Difficult documents (review of 2026-11-01): comments inside and outside the root, a
# processing instruction in the prologue, a DTD, an encoding other than UTF-8. The one with
# the instruction can only be signed enveloping, or enveloped with an Id on the root: DSS
# digests the instructions, and the enveloped (URI="") and detached reference digests cover
# the root element alone.
WITH_COMMENTS = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><!-- nota de dentro --><Titular>PRUEBA FIRMANTE</Titular>"
    b"<Texto>Documento XML de prueba de berigna</Texto><!-- otra nota --></Declaracion>"
)
DIFFICULT = (
    '<?xml version="1.0" encoding="ISO-8859-1"?>'
    "<!-- comentario de fuera -->"
    '<Declaracion texto="café"><!-- nota de dentro --><Titular>PRUEBA FIRMANTE</Titular>'
    "<Texto>acta de sesión de ñandú</Texto></Declaracion>"
    "<!-- final -->"
).encode("ISO-8859-1")
WITH_PI = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<?xml-stylesheet type="text/xsl" href="estilo.xsl"?>'
    "<Declaracion><Texto>con instrucción de procesamiento</Texto></Declaracion>"
)
WITH_PI_AND_ID = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<?xml-stylesheet type="text/xsl" href="estilo.xsl"?>'
    '<Declaracion Id="documento"><Texto>con instrucción de procesamiento</Texto></Declaracion>'
)
WITH_DTD = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<!DOCTYPE Declaracion [<!ENTITY saludo "hola">]>'
    b"<Declaracion>&saludo;</Declaracion>"
)
_HASHES: dict[str, Any] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@dataclass
class Signed:
    result: XadesResult
    leaf: x509.Certificate
    tsa: x509.Certificate
    stamper: FlakyTimeStamper
    card_signatures: int

    @property
    def document(self) -> Any:
        return parse_xml(self.result.data)

    def signature(self) -> Any:
        return signature_element(self.document)

    def unsigned(self) -> list[Any]:
        """The children of UnsignedSignatureProperties, by their local name."""
        qualifying = self.signature().find(".//xades:QualifyingProperties", NS)
        unsigned = qualifying.find("xades:UnsignedProperties", NS)
        if unsigned is None:
            return []
        properties = unsigned.find("xades:UnsignedSignatureProperties", NS)
        return list(properties) if properties is not None else []


def _sign(
    pki: Pki,
    level: SignatureLevel,
    packaging: XadesPackaging = XadesPackaging.ENVELOPED,
    *,
    content: bytes = CONTENT,
    fail_on: frozenset[int] = frozenset(),
    revinfo: bool = True,
    digest: HashAlgorithmName = "sha256",
) -> Signed:
    card, leaf = make_card(pki, "FIRMANTE XADES")
    stamper, tsa_cert = make_timestamper(pki, fail_on)
    context = signing_validation_context(
        pki.store,
        online=False,
        ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa_cert)] if revinfo else [],
        crls=[pki.arl()] if revinfo else [],
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_xades(
            content,
            token,
            (pki.root, pki.ca, leaf),
            packaging=packaging,
            level=level,
            digest=digest,
            reference_uri="datos.xml" if packaging is XadesPackaging.DETACHED else None,
            timestamper=None if level is SignatureLevel.B_B else stamper,
            validation_context=context,
        )
    return Signed(result, leaf, tsa_cert, stamper, card.instructions().count(INS_PSO))


def _name(element: Any) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _verify_the_signature_value(signed: Signed, digest: HashAlgorithmName = "sha256") -> None:
    """The chip's operation verifies with the signer's public key, whatever the level."""
    signed_info = signed.signature().find("ds:SignedInfo", NS)
    value = base64.b64decode(signed.signature().find("ds:SignatureValue", NS).text)
    key = signed.leaf.public_key()
    assert isinstance(key, rsa.RSAPublicKey)
    method = signed_info.find("ds:CanonicalizationMethod", NS).get("Algorithm")
    key.verify(
        value,
        etree.tostring(
            signed_info, method="c14n", exclusive=method == EXC_C14N, with_comments=False
        ),
        padding.PKCS1v15(),
        _HASHES[digest](),
    )


def _without_its_own_signature(document: Any, signature: Any) -> Any:
    """A copy of ``document`` without ``signature`` — only that one: the enveloped transform
    of a signature does not excise the signatures the document already carried."""
    without = copy.deepcopy(document)
    copies = without.findall(".//ds:Signature", NS)
    own = copies[document.findall(".//ds:Signature", NS).index(signature)]
    own.getparent().remove(own)
    return without


def _reference_digest_matches(
    signed: Signed, digest: HashAlgorithmName = "sha256", *, content: bytes = CONTENT
) -> None:
    """Every data-object reference still digests to its DigestValue, whatever was added."""
    document = signed.document
    signature = signature_element(document)  # from the same parse: the enveloped transform
    # excises this signature, and only this one
    for reference in signature.findall("ds:SignedInfo/ds:Reference", NS):
        uri = reference.get("URI")
        transforms = [
            t.get("Algorithm") for t in reference.findall("ds:Transforms/ds:Transform", NS)
        ]
        if uri == "":
            octets = etree.tostring(
                _without_its_own_signature(document, signature),
                method="c14n",
                exclusive=EXC_C14N in transforms,
                with_comments=False,
            )
        elif uri.startswith("#"):
            [target] = signature.getroottree().getroot().xpath(f"//*[@Id='{uri[1:]}']")
            if ENVELOPED in transforms:  # #id on the root: without the signature it carries
                target = _without_its_own_signature(target, signature)
            octets = etree.tostring(
                target, method="c14n", exclusive=EXC_C14N in transforms, with_comments=False
            )
        else:
            octets = etree.tostring(
                parse_xml(content),
                method="c14n",
                exclusive=EXC_C14N in transforms,
                with_comments=False,
            )
        expected = base64.b64encode(hashlib.new(digest, octets).digest()).decode()
        assert reference.find("ds:DigestValue", NS).text == expected, uri


def _token_of(element: Any) -> tsp.TSTInfo:
    encoded = element.find("xades:EncapsulatedTimeStamp", NS).text
    token = cms.ContentInfo.load(base64.b64decode(encoded))
    return tsp.TSTInfo.load(token["content"]["encap_content_info"]["content"].parsed.dump())


@pytest.mark.parametrize("level", list(SignatureLevel))
@pytest.mark.parametrize("packaging", list(XadesPackaging))
def test_every_level_and_packaging_is_valid_and_signed_once(
    pki: Pki, level: SignatureLevel, packaging: XadesPackaging
) -> None:
    signed = _sign(pki, level, packaging)
    assert signed.result.level is level
    assert signed.result.note is None
    assert signed.card_signatures == 1  # one operation in the chip, whatever the level
    _verify_the_signature_value(signed)
    _reference_digest_matches(signed)
    document, signature = signed.document, signed.signature()
    uris = [r.get("URI") for r in signature.findall("ds:SignedInfo/ds:Reference", NS)]
    if packaging is XadesPackaging.ENVELOPED:
        assert _name(document) == "Declaracion"  # RF-030: the signature goes inside
        assert document.find("Titular").text == "PRUEBA FIRMANTE"
        assert document.find(".//ds:Signature", NS) is not None
        assert uris[0] == ""
    elif packaging is XadesPackaging.ENVELOPING:
        assert _name(document) == "Signature"  # RF-031: the content goes inside ds:Object
        assert document.find(".//ds:Object//Titular", NS).text == "PRUEBA FIRMANTE"
        assert uris[0] == "#object"
    else:
        assert _name(document) == "Signature"  # RF-032: the signature references the file
        assert uris[0] == "datos.xml"
    assert signature.find(".//xades:QualifyingProperties", NS) is not None


def test_b_b_has_no_unsigned_properties(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_B)
    assert signed.unsigned() == []
    assert signed.stamper.calls == 0


def test_b_t_carries_a_signature_timestamp(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_T)
    [time_stamp] = signed.unsigned()
    assert _name(time_stamp) == "SignatureTimeStamp"
    assert time_stamp.find("ds:CanonicalizationMethod", NS).get("Algorithm") == EXC_C14N
    value = signed.signature().find("ds:SignatureValue", NS)
    imprint = hashlib.sha256(
        etree.tostring(  # what the property says it covers
            value, method="c14n", exclusive=True, with_comments=False
        )
    ).digest()
    assert _token_of(time_stamp)["message_imprint"]["hashed_message"].native == imprint
    assert signed.result.data.count(b"CertificateValues") == 0  # validation data only from B-LT


def test_b_lt_embeds_the_certificates_and_the_revocation_data(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_LT)
    by_name = {_name(element): element for element in signed.unsigned()}
    embedded = {
        base64.b64decode(cert.text)
        for cert in by_name["CertificateValues"].findall("xades:EncapsulatedX509Certificate", NS)
    }
    der = serialization.Encoding.DER
    for needed in (signed.leaf, pki.ca, signed.tsa):
        assert needed.public_bytes(der) in embedded
    assert pki.root.public_bytes(der) not in embedded  # no anchors
    revocation = by_name["RevocationValues"]
    crls = [
        base64.b64decode(crl.text)
        for crl in revocation.findall("xades:CRLValues/xades:EncapsulatedCRLValue", NS)
    ]
    assert crls == [pki.arl()]
    responses = [
        ocsp.OCSPResponse.load(base64.b64decode(response.text))
        for response in revocation.findall("xades:OCSPValues/xades:EncapsulatedOCSPValue", NS)
    ]
    covered = {
        response["response_bytes"]["response"]
        .parsed["tbs_response_data"]["responses"][0]["cert_id"]["serial_number"]
        .native
        for response in responses
    }
    assert covered == {signed.leaf.serial_number, signed.tsa.serial_number}
    _verify_the_signature_value(signed)  # the signature itself is untouched by the additions


def _archive_imprint(
    signed: Signed, digest: HashAlgorithmName, *, content: bytes = CONTENT
) -> bytes:
    """EN 319 132-1 §5.4.2, recomputed independently of the module: the data objects with
    the enveloped transform (only its own signature excised), exclusive C14N without
    comments: the archive's own and the transform of every reference."""
    document = signed.document
    signature = signature_element(document)  # from the same parse, as above
    h = hashlib.new(digest)
    for reference in signature.findall("ds:SignedInfo/ds:Reference", NS):
        uri = reference.get("URI")
        transforms = [
            t.get("Algorithm") for t in reference.findall("ds:Transforms/ds:Transform", NS)
        ]
        if uri == "":
            h.update(
                etree.tostring(
                    _without_its_own_signature(document, signature),
                    method="c14n",
                    exclusive=True,
                    with_comments=False,
                )
            )
        elif uri.startswith("#"):
            [target] = signature.getroottree().getroot().xpath(f"//*[@Id='{uri[1:]}']")
            if ENVELOPED in transforms:  # #id on the root: without the signature it carries
                target = _without_its_own_signature(target, signature)
            h.update(etree.tostring(target, method="c14n", exclusive=True, with_comments=False))
        else:
            h.update(
                etree.tostring(
                    parse_xml(content), method="c14n", exclusive=True, with_comments=False
                )
            )
    for path in ("ds:SignedInfo", "ds:SignatureValue", "ds:KeyInfo"):
        element = signature.find(path, NS)
        if element is not None:
            h.update(etree.tostring(element, method="c14n", exclusive=True, with_comments=False))
    for element in signed.unsigned():
        if _name(element) != "ArchiveTimeStamp":  # the time-stamp does not cover itself
            h.update(etree.tostring(element, method="c14n", exclusive=True, with_comments=False))
    for obj in signature.findall("ds:Object", NS):
        if obj.find("xades:QualifyingProperties", NS) is None:
            h.update(etree.tostring(obj, method="c14n", exclusive=True, with_comments=False))
    return h.digest()


@pytest.mark.parametrize("digest", ["sha256", "sha512"])
def test_b_lta_archive_timestamp_covers_everything(pki: Pki, digest: HashAlgorithmName) -> None:
    signed = _sign(pki, SignatureLevel.B_LTA, digest=digest)
    [archive] = [element for element in signed.unsigned() if _name(element) == "ArchiveTimeStamp"]
    assert archive.tag == f"{{{XADES141}}}ArchiveTimeStamp"  # XAdES 1.4.1
    info = _token_of(archive)
    assert info["message_imprint"]["hash_algorithm"]["algorithm"].native == digest
    assert info["message_imprint"]["hashed_message"].native == _archive_imprint(signed, digest)
    _reference_digest_matches(signed, digest)


def test_a_tsa_failure_on_the_signature_timestamp_raises(pki: Pki) -> None:
    with pytest.raises(TsaError):
        _sign(pki, SignatureLevel.B_T, fail_on=frozenset({1}))


def test_without_revocation_data_b_lt_stays_at_b_t_and_says_why(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_LT, revinfo=False)
    assert signed.result.level is SignatureLevel.B_T
    assert signed.result.note is not None
    assert signed.result.note.startswith("validation data not embedded")
    assert signed.card_signatures == 1  # the signature already made is kept


def test_a_failed_archive_timestamp_keeps_the_b_lt(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_LTA, fail_on=frozenset({2}))
    assert signed.result.level is SignatureLevel.B_LT
    assert signed.result.note is not None
    assert signed.result.note.startswith("archive time-stamp not added")
    names = {_name(element) for element in signed.unsigned()}
    assert "ArchiveTimeStamp" not in names
    assert {"SignatureTimeStamp", "CertificateValues", "RevocationValues"} <= names


def test_a_tsa_whose_path_cannot_be_built_keeps_the_b_t(pki: Pki) -> None:
    """The same regression as in CAdES: a PathBuildingError after the card has signed must
    lower the level, not lose the signature (review of 2026-10-29)."""
    card, leaf = make_card(pki, "FIRMANTE")
    stamper = unknown_timestamper()
    context = signing_validation_context(
        pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_xades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            level=SignatureLevel.B_LT,
            timestamper=stamper,
            validation_context=context,
        )
    assert result.level is SignatureLevel.B_T
    assert result.note is not None
    assert result.note.startswith("validation data not embedded")
    assert card.instructions().count(INS_PSO) == 1


@pytest.mark.parametrize(
    ("level", "message"),
    [(SignatureLevel.B_T, "a time-stamper"), (SignatureLevel.B_LT, "a validation context")],
)
def test_levels_check_what_they_need(pki: Pki, level: SignatureLevel, message: str) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, _tsa = make_timestamper(pki)
    with DnieV2Token(card) as token, pytest.raises(ValueError, match=message):
        sign_xades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            level=level,
            timestamper=stamper if level is SignatureLevel.B_LT else None,
        )
    assert card.instructions().count(INS_PSO) == 0  # checked before using the card


def test_detached_needs_the_uri_of_the_document(pki: Pki) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token, pytest.raises(ValueError, match="the URI of the document"):
        sign_xades(CONTENT, token, (pki.root, pki.ca, leaf), packaging=XadesPackaging.DETACHED)
    assert card.instructions().count(INS_PSO) == 0


def test_a_document_that_is_not_xml_is_rejected(pki: Pki) -> None:
    """At signing, ERR-30x as in PDF, not the verification code of ERR-401 (review of
    2026-11-01)."""
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token, pytest.raises(XmlFormatError):
        sign_xades(b"esto no es XML", token, (pki.root, pki.ca, leaf))
    assert card.instructions().count(INS_PSO) == 0


def test_a_document_with_a_dtd_is_rejected(pki: Pki) -> None:
    """A DTD can hide entity attacks; it is refused with a message of its own, before the
    card signs (review of 2026-11-01)."""
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token, pytest.raises(XmlDtdError):
        sign_xades(WITH_DTD, token, (pki.root, pki.ca, leaf))
    assert card.instructions().count(INS_PSO) == 0


def test_an_already_signed_document_refuses_the_enveloped_form(pki: Pki) -> None:
    """A second enveloped signature would end up inside what the first one covers, and its
    digest would stop matching: refused before the card signs. The detached and enveloping
    forms do not touch the document and stay available (review of 2026-11-01)."""
    first = _sign(pki, SignatureLevel.B_B)
    card, leaf = make_card(pki, "OTRO FIRMANTE")
    with DnieV2Token(card) as token, pytest.raises(AlreadySignedError):
        sign_xades(first.result.data, token, (pki.root, pki.ca, leaf))
    assert card.instructions().count(INS_PSO) == 0


def test_a_detached_signature_over_an_already_signed_document_keeps_the_first(
    pki: Pki,
) -> None:
    """The detached form signs the file as it is, previous signature included: the first
    signature still digests to its DigestValue (review of 2026-11-01)."""
    first = _sign(pki, SignatureLevel.B_B)
    second = _sign(
        pki, SignatureLevel.B_B, packaging=XadesPackaging.DETACHED, content=first.result.data
    )
    assert second.result.level is SignatureLevel.B_B
    _reference_digest_matches(second, content=first.result.data)
    _reference_digest_matches(first)  # untouched by the second signature


def test_a_document_with_comments_is_archived_without_them(pki: Pki) -> None:
    """XMLDSig digests ``URI=""`` and ``#id`` references with C14N without comments, but
    lxml includes them unless it is told not to: with a comment in the document, the sealed
    octets and the imprint must be the ones a validator recomputes (review of 2026-11-01)."""
    signed = _sign(pki, SignatureLevel.B_LTA, content=WITH_COMMENTS)
    [archive] = [element for element in signed.unsigned() if _name(element) == "ArchiveTimeStamp"]
    info = _token_of(archive)
    assert info["message_imprint"]["hashed_message"].native == _archive_imprint(
        signed, "sha256", content=WITH_COMMENTS
    )
    _reference_digest_matches(signed, content=WITH_COMMENTS)


def test_the_enveloped_output_keeps_the_prologue_and_the_encoding(pki: Pki) -> None:
    """The enveloped form is the original document plus the signature, not a rewritten
    root: the comments outside the root and the ISO-8859-1 encoding of the original survive
    (review of 2026-11-01)."""
    signed = _sign(pki, SignatureLevel.B_LTA, content=DIFFICULT)
    data = signed.result.data
    assert data.startswith(b"<?xml version='1.0' encoding='ISO-8859-1'?>")
    outside = data.index(b"<!-- comentario de fuera -->")
    assert outside < data.index(b"<Declaracion") < data.index(b"<!-- final -->")
    assert "acta de sesión de ñandú".encode("ISO-8859-1") in data  # still ISO-8859-1
    root = parse_xml(data)
    assert root.get("texto") == "café"
    assert root.find(".//ds:Signature", NS) is not None
    _reference_digest_matches(signed, content=DIFFICULT)
    [archive] = [element for element in signed.unsigned() if _name(element) == "ArchiveTimeStamp"]
    assert _token_of(archive)["message_imprint"]["hashed_message"].native == _archive_imprint(
        signed, "sha256", content=DIFFICULT
    )


@pytest.mark.parametrize("packaging", [XadesPackaging.ENVELOPED, XadesPackaging.DETACHED])
def test_instructions_outside_the_root_refuse_the_forms_that_digest_the_document(
    pki: Pki, packaging: XadesPackaging
) -> None:
    """A validator digests the whole document, instructions outside the root included, but
    the enveloped (URI="") and detached reference digests cover the root element alone: the
    signature would not check out, so those forms are refused, before the card signs. DSS
    6.2 says HASH_FAILURE of them (review of 2026-11-01)."""
    card, leaf = make_card(pki, "FIRMANTE")
    with DnieV2Token(card) as token, pytest.raises(XmlPrologueError):
        sign_xades(
            WITH_PI.encode(),
            token,
            (pki.root, pki.ca, leaf),
            packaging=packaging,
            reference_uri="datos.xml" if packaging is XadesPackaging.DETACHED else None,
        )
    assert card.instructions().count(INS_PSO) == 0


def test_an_id_on_the_root_signs_a_document_with_instructions(pki: Pki) -> None:
    """With an Id on the root the reference points at the element, so the instruction
    outside it is genuinely outside the signed data and the signature checks out; the
    reference carries the enveloped transform, which the octets of the archive time-stamp
    apply (DSS 6.2, review of 2026-11-01)."""
    signed = _sign(pki, SignatureLevel.B_LTA, content=WITH_PI_AND_ID.encode())
    signature = signed.signature()
    [reference] = [
        r
        for r in signature.findall("ds:SignedInfo/ds:Reference", NS)
        if r.get("URI") == "#documento"
    ]
    assert ENVELOPED in [
        t.get("Algorithm") for t in reference.findall("ds:Transforms/ds:Transform", NS)
    ]
    assert b'<?xml-stylesheet type="text/xsl" href="estilo.xsl"?>' in signed.result.data
    _reference_digest_matches(signed, content=WITH_PI_AND_ID.encode())
    [archive] = [element for element in signed.unsigned() if _name(element) == "ArchiveTimeStamp"]
    assert _token_of(archive)["message_imprint"]["hashed_message"].native == _archive_imprint(
        signed, "sha256", content=WITH_PI_AND_ID.encode()
    )


def test_the_enveloping_form_signs_a_document_with_instructions(pki: Pki) -> None:
    """The enveloping form embeds the document inside ds:Object: the instructions outside
    its root never enter the signature, and it is the form to offer for them (review of
    2026-11-01)."""
    signed = _sign(
        pki, SignatureLevel.B_LTA, content=WITH_PI.encode(), packaging=XadesPackaging.ENVELOPING
    )
    assert signed.result.level is SignatureLevel.B_LTA
    assert signed.document.find(".//ds:Object//Texto", NS).text == (
        "con instrucción de procesamiento"
    )
    _reference_digest_matches(signed, content=WITH_PI.encode())


def test_the_archive_transform_removes_only_its_own_signature(pki: Pki) -> None:
    """The octets of a ``URI=""`` reference keep the signatures the document already
    carried: the enveloped transform excises only the signature it belongs to, as a
    validator does when recomputing the digest of the first signature (review of
    2026-11-01)."""
    signed = _sign(pki, SignatureLevel.B_B, content=WITH_COMMENTS)
    document = parse_xml(signed.result.data)
    second = etree.fromstring(
        f"<ds:Signature xmlns:ds='{DS}' xmlns:xades='{XADES}' Id='segunda'>"
        "<ds:SignedInfo>"
        "<ds:Reference URI=''><ds:DigestValue>eHg=</ds:DigestValue></ds:Reference>"
        "</ds:SignedInfo>"
        "<ds:SignatureValue>dmFsb3I=</ds:SignatureValue>"
        "<ds:KeyInfo/>"
        "<ds:Object><xades:QualifyingProperties Target='#segunda'>"
        "<xades:UnsignedProperties><xades:UnsignedSignatureProperties/>"
        "</xades:UnsignedProperties></xades:QualifyingProperties></ds:Object>"
        "</ds:Signature>"
    )
    document.append(second)
    stamper, _tsa = make_timestamper(pki)
    asyncio.run(
        _add_archive_timestamp(document, second, parse_xml(WITH_COMMENTS), stamper, "sha256")
    )
    [archive] = [
        element for element in _unsigned_properties(second) if _name(element) == "ArchiveTimeStamp"
    ]
    h = hashlib.sha256()
    h.update(
        etree.tostring(
            _without_its_own_signature(document, second),
            method="c14n",
            exclusive=True,
            with_comments=False,
        )
    )
    for path in ("ds:SignedInfo", "ds:SignatureValue", "ds:KeyInfo"):
        h.update(
            etree.tostring(
                second.find(path, NS), method="c14n", exclusive=True, with_comments=False
            )
        )
    for element in _unsigned_properties(second):
        if _name(element) != "ArchiveTimeStamp":  # the time-stamp does not cover itself
            h.update(etree.tostring(element, method="c14n", exclusive=True, with_comments=False))
    for obj in second.findall("ds:Object", NS):
        if obj.find("xades:QualifyingProperties", NS) is None:  # none: it has only this one
            h.update(etree.tostring(obj, method="c14n", exclusive=True, with_comments=False))
    assert _token_of(archive)["message_imprint"]["hashed_message"].native == h.digest()


def test_repeated_revocation_data_is_embedded_once(pki: Pki) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, tsa_cert = make_timestamper(pki)
    leaf_ocsp, tsa_ocsp, arl = pki.ocsp(leaf), pki.ocsp(tsa_cert), pki.arl()
    context = signing_validation_context(
        pki.store,
        online=False,
        ocsp_responses=[leaf_ocsp, leaf_ocsp, tsa_ocsp],
        crls=[arl, arl],
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_xades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            level=SignatureLevel.B_LT,
            timestamper=stamper,
            validation_context=context,
        )
    signed = Signed(result, leaf, tsa_cert, stamper, 1)
    by_name = {_name(element): element for element in signed.unsigned()}
    revocation = by_name["RevocationValues"]
    assert len(revocation.findall("xades:OCSPValues/xades:EncapsulatedOCSPValue", NS)) == 2
    assert len(revocation.findall("xades:CRLValues/xades:EncapsulatedCRLValue", NS)) == 1


def test_signing_certificate_names_only_the_signer(pki: Pki) -> None:
    """ADR-0008: the signed ``SigningCertificate`` carries the signer certificate alone."""
    signed = _sign(pki, SignatureLevel.B_B)
    [signing] = signed.signature().findall(".//xades:SigningCertificateV2", NS)
    [certificate] = signing.findall("xades:Cert", NS)
    digest = base64.b64decode(certificate.find("xades:CertDigest/ds:DigestValue", NS).text)
    assert digest == hashlib.sha256(to_asn1(signed.leaf).dump()).digest()


def test_a_key_with_an_unexpected_digest_refuses(pki: Pki) -> None:
    """The key signxml sees only signs with the digest the token was set up with."""
    card, leaf = make_card(pki, "FIRMANTE")
    key = _TokenKey(card, leaf.public_key(), "sha256")
    with pytest.raises(ValueError, match="unexpected digest algorithm"):
        key.sign(b"data", padding=None, algorithm=hashes.SHA512())


def test_a_key_with_another_padding_refuses(pki: Pki) -> None:
    """XAdES with RSA is PKCS#1 v1.5 or nothing: the key checks it, not just the digest
    (review of 2026-11-01)."""
    card, leaf = make_card(pki, "FIRMANTE")
    key = _TokenKey(card, leaf.public_key(), "sha256")
    with pytest.raises(ValueError, match="unexpected padding"):
        key.sign(b"data", padding=None, algorithm=hashes.SHA256())


def test_unsigned_properties_need_qualifying_properties() -> None:
    signature = parse_xml(b"<ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'/>")
    with pytest.raises(ValueError, match="no QualifyingProperties"):
        _unsigned_properties(signature)


def test_the_tsa_token_may_carry_no_certificates(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_T)
    [time_stamp] = signed.unsigned()
    der = base64.b64decode(time_stamp.find("xades:EncapsulatedTimeStamp", NS).text)
    token = cms.ContentInfo.load(der)
    token["content"]["certificates"] = cms.CertificateSet([])
    assert token_certificates(token["content"]) == []


def test_revocation_values_carry_only_what_there_is(pki: Pki) -> None:
    """A B-LT without OCSP responses carries CRLValues alone, and the other way round."""
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, tsa_cert = make_timestamper(pki)
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_xades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            level=SignatureLevel.B_T,
            timestamper=stamper,
        )
    signature = signature_element(parse_xml(result.data))
    [time_stamp] = [
        element
        for element in _unsigned_properties(signature)
        if _name(element) == "SignatureTimeStamp"
    ]
    timestamp = base64.b64decode(time_stamp.find("xades:EncapsulatedTimeStamp", NS).text)
    no_check = RevocationCheckingPolicy(
        ee_certificate_rule=RevocationCheckingRule.NO_CHECK,
        intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK,
    )
    for crls, ocsps in (([pki.arl()], []), ([], [pki.ocsp(leaf), pki.ocsp(tsa_cert)])):
        context = signing_validation_context(
            pki.store, online=False, crls=crls, ocsp_responses=ocsps, policy=no_check
        )
        asyncio.run(_add_validation_data(signature, (pki.root, pki.ca, leaf), timestamp, context))
        revocation = _unsigned_properties(signature).find("xades:RevocationValues", NS)
        assert (revocation.find("xades:CRLValues", NS) is not None) == bool(crls)
        assert (revocation.find("xades:OCSPValues", NS) is not None) == bool(ocsps)
        # undo, to test the other case over the same signature
        _unsigned_properties(signature).remove(revocation)
        certificate_values = _unsigned_properties(signature).find("xades:CertificateValues", NS)
        _unsigned_properties(signature).remove(certificate_values)


def test_an_archive_timestamp_without_key_info(pki: Pki) -> None:
    """``ds:KeyInfo`` is optional (XMLDSig; EN 319 132-1): a signature without it, and with
    no references to cover, can still be archived."""
    signature = parse_xml(
        f"<ds:Signature xmlns:ds='{DS}' xmlns:xades='http://uri.etsi.org/01903/v1.3.2#'>"
        "<ds:SignedInfo/><ds:SignatureValue/>"
        "<xades:QualifyingProperties>"
        "<xades:UnsignedProperties><xades:UnsignedSignatureProperties/></xades:UnsignedProperties>"
        "</xades:QualifyingProperties></ds:Signature>"
    )
    stamper, _tsa = make_timestamper(pki)
    asyncio.run(_add_archive_timestamp(signature, signature, parse_xml(CONTENT), stamper, "sha256"))
    [archive] = [
        element
        for element in _unsigned_properties(signature)
        if _name(element) == "ArchiveTimeStamp"
    ]
    assert archive.tag == f"{{{XADES141}}}ArchiveTimeStamp"


@pytest.mark.parametrize("packaging", list(XadesPackaging))
def test_every_reference_declares_its_canonicalization(pki: Pki, packaging: XadesPackaging) -> None:
    """The data object with C14N 1.0 (it keeps the namespace declarations used only inside
    values); SignedProperties and KeyInfo with exclusive C14N (nothing inherited from the
    root). Both come from overriding private hooks of signxml: if they stop being called,
    this fails (2026-11-02)."""
    signature = _sign(pki, SignatureLevel.B_B, packaging).signature()
    for reference in signature.findall("ds:SignedInfo/ds:Reference", NS):
        transforms = [
            t.get("Algorithm") for t in reference.findall("ds:Transforms/ds:Transform", NS)
        ]
        internal = reference.get("Type") or reference.get("URI", "").startswith("#SignXMLCert")
        expected = EXC_C14N if internal else "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        assert transforms[-1] == expected, reference.get("URI")
    method = signature.find("ds:SignedInfo/ds:CanonicalizationMethod", NS).get("Algorithm")
    assert method == EXC_C14N
