# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""CAdES through the DNIe v2 driver (simulator) and a test TSA: PR-CAD-01 to PR-CAD-08,
RF-020 to RF-022. The external validation with DSS 6.2 is tests/interop/matriz_cades.py."""

import asyncio
import hashlib
from dataclasses import dataclass

import pytest
from asn1crypto import cms, core, ocsp, tsp
from cryptography import x509
from pyhanko.sign.validation import async_validate_cms_signature, async_validate_detached_cms
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import RevocationCheckingPolicy, RevocationCheckingRule

from berigna.core.certs import to_asn1
from berigna.core.errors import TsaError
from berigna.core.formats.cades import (
    OID_ARCHIVE_TIME_STAMP_V3,
    OID_ATS_HASH_INDEX_V3,
    AtsHashIndexV3,
    CadesPackaging,
    CadesResult,
    _add_validation_data,
    sign_cades,
    signature_timestamp,
    signer_certificate,
)
from berigna.core.formats.common import SignatureLevel
from berigna.core.token.base import HashAlgorithmName
from berigna.core.token.dnie_v2 import INS_PSO, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import signing_validation_context
from support.cards import make_card
from support.pki import Pki, build_pki
from support.tsa import FlakyTimeStamper, make_timestamper, unknown_timestamper

CONTENT = b"Contrato de prueba de berigna\n" * 20


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@dataclass
class Signed:
    result: CadesResult
    leaf: x509.Certificate
    tsa: x509.Certificate
    stamper: FlakyTimeStamper
    card_signatures: int

    @property
    def signed_data(self) -> cms.SignedData:
        return cms.ContentInfo.load(self.result.data)["content"]

    def unsigned(self) -> dict[str, cms.CMSAttribute]:
        attributes = self.signed_data["signer_infos"][0]["unsigned_attrs"]
        return (
            {} if isinstance(attributes, core.Void) else {a["type"].dotted: a for a in attributes}
        )


def _sign(
    pki: Pki,
    level: SignatureLevel,
    packaging: CadesPackaging = CadesPackaging.DETACHED,
    *,
    fail_on: frozenset[int] = frozenset(),
    revinfo: bool = True,
    digest: HashAlgorithmName = "sha256",
) -> Signed:
    card, leaf = make_card(pki, "FIRMANTE CADES")
    stamper, tsa_cert = make_timestamper(pki, fail_on)
    context = signing_validation_context(
        pki.store,
        online=False,
        ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa_cert)] if revinfo else [],
        crls=[pki.arl()] if revinfo else [],
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_cades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            packaging=packaging,
            level=level,
            digest=digest,
            timestamper=None if level is SignatureLevel.B_B else stamper,
            validation_context=context,
        )
    return Signed(result, leaf, tsa_cert, stamper, card.instructions().count(INS_PSO))


def _context(pki: Pki) -> ValidationContext:
    return ValidationContext(trust_roots=[to_asn1(pki.root)], other_certs=[to_asn1(pki.ca)])


@pytest.mark.parametrize("level", list(SignatureLevel))
@pytest.mark.parametrize("packaging", list(CadesPackaging))
def test_every_level_and_packaging_is_valid_and_signed_once(
    pki: Pki, level: SignatureLevel, packaging: CadesPackaging
) -> None:
    signed = _sign(pki, level, packaging)
    assert signed.result.level is level
    assert signed.result.note is None
    assert signed.card_signatures == 1  # one operation in the chip, whatever the level
    signed_data = signed.signed_data
    encapsulated = signed_data["encap_content_info"]["content"]
    if packaging is CadesPackaging.DETACHED:
        assert not encapsulated.native  # RF-020: the .p7s does not carry the file
        status = asyncio.run(async_validate_detached_cms(CONTENT, signed_data, _context(pki)))
    else:
        assert encapsulated.native == CONTENT  # RF-021: the .p7m carries it
        status = asyncio.run(
            async_validate_cms_signature(signed_data, validation_context=_context(pki))
        )
    assert status.intact
    assert status.valid
    assert status.trusted
    signed_attrs = {a["type"].native for a in signed_data["signer_infos"][0]["signed_attrs"]}
    assert {"content_type", "message_digest", "signing_certificate_v2"} <= signed_attrs


def test_b_b_has_no_unsigned_attributes(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_B)
    assert signed.unsigned() == {}
    assert signed.stamper.calls == 0


def test_b_t_carries_a_signature_timestamp(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_T)
    assert list(signed.unsigned()) == ["1.2.840.113549.1.9.16.2.14"]  # signature-time-stamp
    assert not signed.signed_data["crls"].native  # validation data only from B-LT


def test_b_lt_embeds_the_certificates_and_the_revocation_data(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_LT)
    signed_data = signed.signed_data
    certificates = {c.chosen.dump() for c in signed_data["certificates"]}
    for needed in (signed.leaf, pki.ca, signed.tsa):
        assert to_asn1(needed).dump() in certificates
    assert to_asn1(pki.root).dump() not in certificates  # the anchor is not embedded
    choices = list(signed_data["crls"])
    crls = [c.chosen for c in choices if c.name == "crl"]
    others = [c.chosen for c in choices if c.name == "other"]
    assert [crl.dump() for crl in crls] == [pki.arl()]
    assert {o["other_rev_info_format"].native for o in others} == {"ocsp_response"}
    covered = {
        ocsp.OCSPResponse.load(o["other_rev_info"].dump())["response_bytes"]["response"]
        .parsed["tbs_response_data"]["responses"][0]["cert_id"]["serial_number"]
        .native
        for o in others
    }
    assert covered == {signed.leaf.serial_number, signed.tsa.serial_number}
    assert signed_data["version"].native == "v5"  # RFC 5652: "other" revocation information
    # The signature itself is untouched by the unsigned additions.
    assert asyncio.run(async_validate_detached_cms(CONTENT, signed_data, _context(pki))).intact


def _imprint(signed_data: cms.SignedData, index: AtsHashIndexV3, digest: str) -> bytes:
    signer_info = signed_data["signer_infos"][0]
    fields = b"".join(
        signer_info[name].dump()
        for name in (
            "version",
            "sid",
            "digest_algorithm",
            "signed_attrs",
            "signature_algorithm",
            "signature",
        )
    )
    data = (
        signed_data["encap_content_info"]["content_type"].dump()
        + hashlib.new(digest, CONTENT).digest()
        + fields
        + index.dump()
    )
    return hashlib.new(digest, data).digest()


@pytest.mark.parametrize("digest", ["sha256", "sha512"])
def test_b_lta_archive_timestamp_covers_the_hash_index(pki: Pki, digest: HashAlgorithmName) -> None:
    """EN 319 122-1 §5.5.3, recomputed independently of the module."""
    signed = _sign(pki, SignatureLevel.B_LTA, digest=digest)
    unsigned = signed.unsigned()
    assert list(unsigned) == ["1.2.840.113549.1.9.16.2.14", OID_ARCHIVE_TIME_STAMP_V3]
    token = cms.ContentInfo.load(unsigned[OID_ARCHIVE_TIME_STAMP_V3]["values"][0].dump())
    token_info = token["content"]["signer_infos"][0]
    [index_attribute] = [
        a for a in token_info["unsigned_attrs"] if a["type"].dotted == OID_ATS_HASH_INDEX_V3
    ]
    index = AtsHashIndexV3.load(index_attribute["values"][0].dump())
    assert index["hash_ind_algorithm"]["algorithm"].native == digest  # encoded explicitly
    signed_data = signed.signed_data
    assert len(index["certificates_hash_index"]) == len(signed_data["certificates"])
    assert len(index["crls_hash_index"]) == len(signed_data["crls"])
    assert len(index["unsigned_attr_values_hash_index"]) == 1  # the signature time-stamp
    info = tsp.TSTInfo.load(token["content"]["encap_content_info"]["content"].parsed.dump())
    imprint = info["message_imprint"]
    assert imprint["hash_algorithm"]["algorithm"].native == digest
    assert imprint["hashed_message"].native == _imprint(signed_data, index, digest)


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
    assert OID_ARCHIVE_TIME_STAMP_V3 not in signed.unsigned()
    assert signed.signed_data["crls"].native  # the B-LT data is there


@pytest.mark.parametrize(
    ("level", "message"),
    [(SignatureLevel.B_T, "a time-stamper"), (SignatureLevel.B_LT, "a validation context")],
)
def test_levels_check_what_they_need(pki: Pki, level: SignatureLevel, message: str) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, _tsa = make_timestamper(pki)
    with DnieV2Token(card) as token, pytest.raises(ValueError, match=message):
        sign_cades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            level=level,
            timestamper=stamper if level is SignatureLevel.B_LT else None,
        )
    assert card.instructions().count(INS_PSO) == 0  # checked before using the card


def test_signer_certificate_by_key_identifier_or_missing(pki: Pki) -> None:
    signed_data = _sign(pki, SignatureLevel.B_B).signed_data
    certificate = signer_certificate(signed_data)
    signer_info = signed_data["signer_infos"][0]
    signer_info["sid"] = cms.SignerIdentifier(
        {"subject_key_identifier": certificate.public_key.sha1}  # no SKI extension in the test PKI
    )
    assert signer_certificate(signed_data).dump() == certificate.dump()
    signed_data["certificates"] = cms.CertificateSet([])
    with pytest.raises(ValueError, match="not embedded"):
        signer_certificate(signed_data)


def test_signer_certificate_among_several(pki: Pki) -> None:
    """In a B-LT the signer is one of several embedded certificates."""
    signed = _sign(pki, SignatureLevel.B_LT)
    signed_data = signed.signed_data
    assert signer_certificate(signed_data).dump() == to_asn1(signed.leaf).dump()
    certificate = signer_certificate(signed_data)
    signed_data["signer_infos"][0]["sid"] = cms.SignerIdentifier(
        {"subject_key_identifier": certificate.public_key.sha1}
    )
    assert signer_certificate(signed_data).dump() == certificate.dump()


def test_signature_timestamp_is_found_wherever_it_is(pki: Pki) -> None:
    assert (
        signature_timestamp(_sign(pki, SignatureLevel.B_B).signed_data["signer_infos"][0]) is None
    )
    signer_info = _sign(pki, SignatureLevel.B_T).signed_data["signer_infos"][0]
    # A short unknown attribute: DER orders the SET OF so that it comes first.
    other = cms.CMSAttribute({"type": "1.2.3", "values": [core.Null()]})
    signer_info["unsigned_attrs"] = cms.CMSAttributes([*signer_info["unsigned_attrs"], other])
    assert signer_info["unsigned_attrs"][0]["type"].dotted == "1.2.3"
    timestamp = signature_timestamp(signer_info)
    assert timestamp is not None
    assert timestamp["encap_content_info"]["content_type"].native == "tst_info"


def test_validation_data_without_a_timestamp_or_ocsp(pki: Pki) -> None:
    """Only the signer's path when there is no time-stamp; no OCSP: CMS version unchanged."""
    signed = _sign(pki, SignatureLevel.B_B)
    no_check = RevocationCheckingPolicy(
        ee_certificate_rule=RevocationCheckingRule.NO_CHECK,
        intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK,
    )
    context = signing_validation_context(pki.store, online=False, policy=no_check)
    content = cms.ContentInfo.load(signed.result.data)
    extended = asyncio.run(_add_validation_data(content, to_asn1(signed.leaf), context))
    signed_data = extended["content"]
    assert signed_data["version"].native == "v1"
    assert isinstance(signed_data["crls"], core.Void)  # no empty [1] SET
    certificates = {c.chosen.dump() for c in signed_data["certificates"]}
    assert certificates == {to_asn1(signed.leaf).dump(), to_asn1(pki.ca).dump()}


def test_a_tsa_whose_path_cannot_be_built_keeps_the_b_t(pki: Pki) -> None:
    """Review of 2026-10-29: PathBuildingError escaped after the card had signed, and the
    signature authorised with the PIN was lost. Now it lowers the level, with the reason."""
    card, leaf = make_card(pki, "FIRMANTE")
    stamper = unknown_timestamper()  # its path cannot be built: PathBuildingError
    context = signing_validation_context(
        pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_cades(
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
        result = sign_cades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            level=SignatureLevel.B_LT,
            timestamper=stamper,
            validation_context=context,
        )
    revocation = list(cms.ContentInfo.load(result.data)["content"]["crls"])
    assert len(revocation) == 3  # one CRL and two OCSP responses
