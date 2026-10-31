# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verification of CAdES (RF-051, RF-053, RF-056): indications, time-stamps and B-LTA.

The signatures come from berigna's own signer with the DNIe simulator, as validated
externally by DSS 6.2 in ``tests/interop/matriz_cades.py`` (SPK-03). As in the PDF module, a
hostile CMS that breaks pyHanko or asn1crypto past the digest is still an ETSI result
(TOTAL-FAILED/FORMAT_FAILURE), never an unexpected error (AM-05)."""

import datetime as dt

import pytest
import requests
from asn1crypto import cms, core
from asn1crypto import crl as asn1_crl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from berigna.core.errors import UnreadableSignatureError
from berigna.core.formats.cades import CadesPackaging, sign_cades
from berigna.core.formats.common import SignatureLevel
from berigna.core.token.dnie_v2 import CertificateSlot, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import (
    cades_content,
    signing_validation_context,
    verify_cades,
)
from berigna.core.validation.spec import Indication
from sim.dnie_v2 import DnieV2Simulator
from support.cards import make_card
from support.pki import NOW, Pki, build_pki
from support.tsa import make_timestamper

CONTENT = b"Documento de prueba de berigna (verificacion CAdES)\n" * 40
TSA_NAME = "CN=TEST TSA,C=PE"

_LEVELS = [SignatureLevel.B_B, SignatureLevel.B_T, SignatureLevel.B_LT, SignatureLevel.B_LTA]
_PACKAGINGS = [CadesPackaging.DETACHED, CadesPackaging.ENVELOPING]


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _card(leaf: x509.Certificate, key: rsa.RSAPrivateKey) -> DnieV2Simulator:
    """A card with one certificate; lets the tests change the leaf (RF-056)."""
    return DnieV2Simulator(
        files={CertificateSlot.SIGNATURE.value: leaf.public_bytes(serialization.Encoding.DER)},
        private_key=key,
    )


def _sign(
    pki: Pki,
    level: SignatureLevel = SignatureLevel.B_B,
    packaging: CadesPackaging = CadesPackaging.DETACHED,
    *,
    ts_pki: Pki | None = None,
    leaf_days: tuple[int, int] | None = None,
) -> tuple[bytes, x509.Certificate, x509.Certificate]:
    """berigna's own CAdES at ``level``, signed through the DNIe simulator against the store
    of the test PKI. ``ts_pki`` gives the time-stamps of another PKI; ``leaf_days`` makes
    an expiring certificate (RF-056). Returns the CMS, the signer and the TSA of the stamps."""
    if leaf_days is not None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = pki.leaf("FIRMANTE CADES", key=key, days=leaf_days)
        card = _card(leaf, key)
    else:
        card, leaf = make_card(pki, "FIRMANTE CADES")
    stamper, tsa = make_timestamper(ts_pki if ts_pki is not None else pki)
    long_term = level in (SignatureLevel.B_LT, SignatureLevel.B_LTA)
    context = (
        signing_validation_context(
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
            crls=[pki.arl()],
        )
        if long_term
        else None
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_cades(
            CONTENT,
            token,
            (pki.root, pki.ca, leaf),
            packaging=packaging,
            level=level,
            timestamper=None if level is SignatureLevel.B_B else stamper,
            validation_context=context,
        )
    return result.data, leaf, tsa


@pytest.mark.parametrize("level", _LEVELS)
@pytest.mark.parametrize("packaging", _PACKAGINGS)
def test_berigna_cades_verifies(pki: Pki, level: SignatureLevel, packaging: CadesPackaging) -> None:
    """Every level and packaging that berigna signs is verified successfully (RF-051).
    Without revocation data the B-B and the B-T are INDETERMINATE (ETSI: the revocation of
    the signer cannot be proved), exactly like the same levels in PAdES; the B-LT and the
    B-LTA embed all their data, so they pass offline."""
    signature, leaf, _ = _sign(pki, level, packaging)
    content = None if packaging is CadesPackaging.ENVELOPING else CONTENT
    [report] = verify_cades(signature, pki.store, content=content, online=False).signatures
    if level in (SignatureLevel.B_B, SignatureLevel.B_T):
        assert report.indication is Indication.INDETERMINATE
        assert report.subindication == "TRY_LATER"
    else:
        assert report.indication is Indication.TOTAL_PASSED
        assert report.subindication is None
    assert report.signer == leaf
    assert report.packaging is packaging


def test_a_b_t_reports_its_timestamp(pki: Pki) -> None:
    """RF-053: the signature time-stamp carries its own indication, name and time. Without
    revocation data the signature itself stays INDETERMINATE (like in PAdES); here the
    revocation data of the signer, of the CA and of the TSA are supplied."""
    signature, leaf, tsa_cert = _sign(pki, SignatureLevel.B_T)
    [report] = verify_cades(
        signature,
        pki.store,
        content=CONTENT,
        online=False,
        ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa_cert)],
        crls=[pki.arl()],
    ).signatures
    assert report.indication is Indication.TOTAL_PASSED
    stamp = report.timestamp
    assert stamp is not None
    assert stamp.indication is Indication.TOTAL_PASSED
    assert stamp.time is not None
    assert stamp.tsa is not None
    assert stamp.tsa.subject.rfc4514_string() == TSA_NAME
    assert report.archive_timestamps == ()


def test_a_b_lta_reports_its_archive_timestamp(pki: Pki) -> None:
    """B-LTA: the archive time-stamp is verified on its own and reports time and TSA."""
    signature, _, _ = _sign(pki, SignatureLevel.B_LTA)
    [report] = verify_cades(signature, pki.store, content=CONTENT, online=False).signatures
    assert report.indication is Indication.TOTAL_PASSED
    [stamp] = report.archive_timestamps
    assert stamp.indication is Indication.TOTAL_PASSED
    assert stamp.time is not None
    assert stamp.tsa is not None
    assert stamp.tsa.subject.rfc4514_string() == TSA_NAME


def test_supplied_revocation_data_verifies_a_b_b(pki: Pki) -> None:
    """The caller supplies the revocation data of the signer and of the CA: the B-B
    validates completely offline without the CMS embedding any data."""
    signature, leaf, _ = _sign(pki)
    [report] = verify_cades(
        signature,
        pki.store,
        content=CONTENT,
        online=False,
        ocsp_responses=[pki.ocsp(leaf)],
        crls=[pki.arl()],
    ).signatures
    assert report.indication is Indication.TOTAL_PASSED
    assert report.subindication is None


def test_a_revoked_signer_is_reported(pki: Pki) -> None:
    signature, leaf, _ = _sign(pki)
    [report] = verify_cades(
        signature,
        pki.store,
        content=CONTENT,
        online=False,
        ocsp_responses=[pki.ocsp(leaf, revoked=True)],
        crls=[pki.arl()],
    ).signatures
    assert report.indication is Indication.INDETERMINATE
    assert report.subindication == "REVOKED_NO_POE"


def test_a_signer_outside_the_trust_store_is_indeterminate(pki: Pki) -> None:
    other = build_pki()
    signature, _, _ = _sign(other)
    [report] = verify_cades(signature, pki.store, content=CONTENT, online=False).signatures
    assert report.indication is Indication.INDETERMINATE


def test_a_timestamp_from_an_untrusted_tsa_is_reported(pki: Pki) -> None:
    signature, _, _ = _sign(pki, SignatureLevel.B_T, ts_pki=build_pki())
    [report] = verify_cades(signature, pki.store, content=CONTENT, online=False).signatures
    assert report.indication is not Indication.TOTAL_PASSED
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.INDETERMINATE


def test_altered_content_fails_the_hash_check(pki: Pki) -> None:
    signature, _, _ = _sign(pki)
    [report] = verify_cades(
        signature, pki.store, content=CONTENT + b" (modificado)", online=False
    ).signatures
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "HASH_FAILURE"


def test_an_expired_certificate_without_timestamp_is_indeterminate(pki: Pki) -> None:
    """RF-056: without a time-stamp, an expired certificate is only an INDETERMINATE."""
    signature, _, _ = _sign(pki, leaf_days=(-10, 1))
    [report] = verify_cades(
        signature,
        pki.store,
        content=CONTENT,
        online=False,
        moment=NOW + dt.timedelta(days=400),
    ).signatures
    assert report.indication is Indication.INDETERMINATE


def test_an_expired_certificate_passes_with_proof_of_existence(pki: Pki) -> None:
    """RF-056: the time-stamp of the signature proves that the signature existed while the
    certificate was valid. The TSA needs its revocation data at that moment: supplied here,
    fetched online in real use (the CMS of an unreviewed B-T has no revocation data)."""
    signature, _, tsa_cert = _sign(pki, SignatureLevel.B_T, leaf_days=(-10, 1))
    moment = NOW + dt.timedelta(days=3)
    [report] = verify_cades(
        signature,
        pki.store,
        content=CONTENT,
        online=False,
        moment=moment,
        ocsp_responses=[pki.ocsp(tsa_cert, at=moment)],
        crls=[pki.arl()],
    ).signatures
    assert report.indication is Indication.TOTAL_PASSED
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.TOTAL_PASSED


def test_a_detached_signature_without_content_is_an_error(pki: Pki) -> None:
    """RF-051: a ``.p7s`` without the file it signs cannot be checked for integrity."""
    signature, _, _ = _sign(pki)
    with pytest.raises(UnreadableSignatureError) as info:
        verify_cades(signature, pki.store, online=False)
    assert info.value.code == "ERR-402"


def test_bytes_that_are_not_a_cms_are_an_error(pki: Pki) -> None:
    with pytest.raises(UnreadableSignatureError) as info:
        verify_cades(b"no es un CMS", pki.store)
    assert info.value.code == "ERR-402"


def test_a_content_type_that_is_not_signed_data_is_an_error(pki: Pki) -> None:
    cms_info = cms.ContentInfo({"content_type": "data", "content": core.OctetString(CONTENT)})
    with pytest.raises(UnreadableSignatureError) as info:
        verify_cades(cms_info.dump(), pki.store)
    assert info.value.code == "ERR-402"


def test_a_cms_without_signer_infos_is_an_error(pki: Pki) -> None:
    cms_info = cms.ContentInfo(
        {
            "content_type": "signed_data",
            "content": {
                "version": "v1",
                "digest_algorithms": [],
                "encap_content_info": {"content_type": "data"},
                "signer_infos": [],
            },
        }
    )
    with pytest.raises(UnreadableSignatureError) as info:
        verify_cades(cms_info.dump(), pki.store, content=CONTENT)
    assert info.value.code == "ERR-402"


def test_cades_content_extracts_the_encapsulated_file(pki: Pki) -> None:
    detached, _, _ = _sign(pki)
    enveloping, _, _ = _sign(pki, packaging=CadesPackaging.ENVELOPING)
    assert cades_content(detached) is None
    assert cades_content(enveloping) == CONTENT


def test_the_encapsulated_content_of_a_p7m_tampered_is_a_hash_failure(pki: Pki) -> None:
    """The wrapped content gone: only the signature fails; the archive time-stamp covers
    the production of the pieces of the CMS, not the content (§5.5.2)."""
    signature, _, _ = _sign(pki, SignatureLevel.B_LTA, CadesPackaging.ENVELOPING)
    info = cms.ContentInfo.load(signature)
    encap = bytearray(bytes(info["content"]["encap_content_info"]["content"]))
    encap[-1] ^= 0x2A
    info["content"]["encap_content_info"]["content"] = core.ParsableOctetString(bytes(encap))
    tampered = info.dump(force=True)
    assert tampered != signature
    [report] = verify_cades(tampered, pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "HASH_FAILURE"
    [stamp] = report.archive_timestamps
    assert stamp.indication is Indication.TOTAL_PASSED


def test_a_cms_that_changed_after_the_archive_stamp_fails_its_coverage(pki: Pki) -> None:
    """RF-053: the CMS is still verifiable, but the archive time-stamp no longer covers it:
    one more CRL in the hash index of the CMS, whose archive time-stamp was computed
    against the hash index without that CRL."""
    signature, _, _ = _sign(pki, SignatureLevel.B_LTA)
    extra = asn1_crl.CertificateList.load(pki.arl())
    info = cms.ContentInfo.load(signature)
    signed_data = info["content"]
    crls = [] if isinstance(signed_data["crls"], core.Void) else list(signed_data["crls"])
    signed_data["crls"] = cms.RevocationInfoChoices(
        [*crls, cms.RevocationInfoChoice(name="crl", value=extra)]
    )
    tampered = info.dump(force=True)
    [report] = verify_cades(tampered, pki.store, content=CONTENT, online=False).signatures
    assert report.indication is Indication.TOTAL_PASSED  # the signature keeps passing
    [stamp] = report.archive_timestamps
    assert stamp.indication is Indication.TOTAL_FAILED
    assert stamp.subindication == "HASH_FAILURE"


@pytest.mark.parametrize(
    ("hook", "level"),
    [
        ("_signature_timestamp_report", SignatureLevel.B_T),
        ("_archive_tokens", SignatureLevel.B_LTA),
    ],
)
def test_hostile_cms_past_the_digest_is_a_format_failure(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, hook: str, level: SignatureLevel
) -> None:
    """A time-stamp process that breaks is still an ETSI result (AM-05), as in the PDF
    verifier (the same hostile tests patch his own steps)."""
    from berigna.core.validation import cades as module

    def broken(*_args: object) -> object:
        raise KeyError("hostile")

    monkeypatch.setattr(module, hook, broken)
    signature, _, _ = _sign(pki, level)
    [report] = verify_cades(signature, pki.store, content=CONTENT, online=False).signatures
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "FORMAT_FAILURE"
    assert report.signer is None


def test_online_verification_with_unreachable_services(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    urls: list[str] = []

    def refuse(url: str, *args: object, **kwargs: object) -> requests.Response:
        urls.append(url)
        raise requests.ConnectionError(f"no route to {url}")

    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    signature, _, _ = _sign(pki)
    [report] = verify_cades(
        signature, pki.store, content=CONTENT, online=True, timeout=1.0
    ).signatures
    assert report.indication is Indication.INDETERMINATE
    assert urls  # the services named in the certificate were tried
