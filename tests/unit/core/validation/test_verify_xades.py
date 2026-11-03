# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verification of XAdES (RF-052, RF-053, RF-056): indications, time-stamps, B-LTA and the
XML attacks of AM-06 (PR-VAL-08).

The signatures come from berigna's own signer with the DNIe simulator, as validated
externally by DSS 6.2 in ``tests/interop/matriz_xades.py``; the signatures that DSS itself
generates are verified in ``tests/interop/firmas_dss.py`` (PR-INT-06). A hostile signature
is always an ETSI result or a reading error, never an unexpected exception (AM-05)."""

import base64
import copy
import datetime as dt
import hashlib
from typing import Any

import pytest
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from lxml import etree
from signxml import methods
from signxml.xades.xades import XAdESSigner

from berigna.core.errors import UnreadableDocumentError, UnreadableSignatureError
from berigna.core.formats.common import SignatureLevel
from berigna.core.formats.xades import DS, NS, XADES, XadesPackaging, sign_xades
from berigna.core.token.dnie_v2 import CertificateSlot, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import signing_validation_context
from berigna.core.validation.spec import Indication
from berigna.core.validation.xades import SignedScope, verify_xades
from sim.dnie_v2 import DnieV2Simulator
from support.cards import make_card
from support.pki import NOW, Pki, build_pki
from support.tsa import make_timestamper

CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><!-- nota --><Titular>PRUEBA FIRMANTE</Titular>"
    b"<Texto>Documento XML de prueba de berigna (verificacion XAdES)</Texto></Declaracion>"
)
TSA_NAME = "CN=TEST TSA,C=PE"
URI = "datos.xml"


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _sign(
    pki: Pki,
    level: SignatureLevel = SignatureLevel.B_B,
    packaging: XadesPackaging = XadesPackaging.ENVELOPED,
    *,
    content: bytes = CONTENT,
    ts_pki: Pki | None = None,
    leaf_days: tuple[int, int] | None = None,
) -> tuple[bytes, x509.Certificate, x509.Certificate]:
    """berigna's own XAdES at ``level``, signed through the DNIe simulator. ``ts_pki`` gives
    the time-stamps of another PKI; ``leaf_days`` makes an expiring certificate (RF-056).
    Returns the signed document, the signer and the TSA of the stamps."""
    if leaf_days is not None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = pki.leaf("FIRMANTE XADES", key=key, days=leaf_days)
        card: Any = DnieV2Simulator(
            files={CertificateSlot.SIGNATURE.value: leaf.public_bytes(serialization.Encoding.DER)},
            private_key=key,
        )
    else:
        card, leaf = make_card(pki, "FIRMANTE XADES")
    stamper, tsa = make_timestamper(ts_pki if ts_pki is not None else pki)
    context = signing_validation_context(
        pki.store,
        online=False,
        ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
        crls=[pki.arl()],
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_xades(
            content,
            token,
            (pki.root, pki.ca, leaf),
            packaging=packaging,
            level=level,
            reference_uri=URI if packaging is XadesPackaging.DETACHED else None,
            timestamper=None if level is SignatureLevel.B_B else stamper,
            validation_context=context,
        )
    return result.data, leaf, tsa


def _verify(signed: bytes, pki: Pki, **kwargs: Any) -> Any:
    [report] = verify_xades(signed, pki.store, online=False, **kwargs).signatures
    return report


def _edit(signed: bytes, change: Any) -> bytes:
    """``signed`` after ``change(root)``, serialized again."""
    root = etree.fromstring(signed)
    change(root)
    return bytes(etree.tostring(root, xml_declaration=True, encoding="UTF-8"))


def _signature(root: Any) -> Any:
    return root if root.tag == f"{{{DS}}}Signature" else root.find(".//ds:Signature", NS)


# -- every level and packaging ---------------------------------------------------------------------


@pytest.mark.parametrize("level", list(SignatureLevel))
@pytest.mark.parametrize("packaging", list(XadesPackaging))
def test_berigna_xades_verifies(pki: Pki, level: SignatureLevel, packaging: XadesPackaging) -> None:
    """Every level and packaging that berigna signs verifies (RF-052). Without revocation
    data the B-B and the B-T are INDETERMINATE, as in PAdES and CAdES; the B-LT and the
    B-LTA embed their data and pass offline. The comment in the document is not signed
    (XMLDSig), and does not break anything."""
    signed, leaf, _ = _sign(pki, level, packaging)
    report = _verify(signed, pki, content=CONTENT if packaging is XadesPackaging.DETACHED else None)
    if level in (SignatureLevel.B_B, SignatureLevel.B_T):
        assert report.indication is Indication.INDETERMINATE
        assert report.subindication == "TRY_LATER"
    else:
        assert report.indication is Indication.TOTAL_PASSED
        assert report.subindication is None
    assert report.signer == leaf
    assert report.packaging is packaging
    assert report.claimed_signing_time is not None
    assert (
        report.scope
        is {
            XadesPackaging.ENVELOPED: SignedScope.DOCUMENT,
            XadesPackaging.ENVELOPING: SignedScope.OBJECT,
            XadesPackaging.DETACHED: SignedScope.EXTERNAL,
        }[packaging]
    )
    assert len(report.references) == 1
    assert len(report.archive_timestamps) == (1 if level is SignatureLevel.B_LTA else 0)


def test_a_b_t_reports_its_timestamp(pki: Pki) -> None:
    """RF-053: the signature time-stamp carries its own indication, name and time; with the
    revocation data of the signer, the CA and the TSA, the B-T passes."""
    signed, leaf, tsa = _sign(pki, SignatureLevel.B_T)
    report = _verify(signed, pki, ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)], crls=[pki.arl()])
    assert report.indication is Indication.TOTAL_PASSED
    stamp = report.timestamp
    assert stamp is not None
    assert stamp.indication is Indication.TOTAL_PASSED
    assert stamp.time is not None
    assert stamp.tsa is not None
    assert stamp.tsa.subject.rfc4514_string() == TSA_NAME


def test_supplied_revocation_data_verifies_a_b_b(pki: Pki) -> None:
    signed, leaf, _ = _sign(pki)
    report = _verify(signed, pki, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()])
    assert report.indication is Indication.TOTAL_PASSED
    assert report.timestamp is None


def test_a_b_lta_reports_its_archive_timestamp(pki: Pki) -> None:
    signed, _, _ = _sign(pki, SignatureLevel.B_LTA)
    [stamp] = _verify(signed, pki).archive_timestamps
    assert stamp.indication is Indication.TOTAL_PASSED
    assert stamp.tsa is not None
    assert stamp.tsa.subject.rfc4514_string() == TSA_NAME


def test_a_signature_changed_after_the_archive_stamp_fails_its_coverage(pki: Pki) -> None:
    """PR-TSA-05: one more certificate in CertificateValues after the archive time-stamp.
    The signature keeps passing; the archive time-stamp no longer covers it."""

    def add_certificate(root: Any) -> None:
        values = root.find(".//xades:CertificateValues", NS)
        extra = etree.SubElement(values, f"{{{XADES}}}EncapsulatedX509Certificate")
        extra.text = base64.b64encode(pki.ca.public_bytes(serialization.Encoding.DER)).decode()

    signed, _, _ = _sign(pki, SignatureLevel.B_LTA)
    report = _verify(_edit(signed, add_certificate), pki)
    assert report.indication is Indication.TOTAL_PASSED
    [stamp] = report.archive_timestamps
    assert stamp.indication is Indication.TOTAL_FAILED
    assert stamp.subindication == "HASH_FAILURE"


def test_a_timestamp_from_an_untrusted_tsa_is_reported(pki: Pki) -> None:
    signed, _, _ = _sign(pki, SignatureLevel.B_T, ts_pki=build_pki())
    report = _verify(signed, pki)
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.INDETERMINATE


# -- integrity (PR-VAL-01) -------------------------------------------------------------------------


def test_an_altered_document_fails_the_hash_check(pki: Pki) -> None:
    signed, leaf, _ = _sign(pki)
    report = _verify(signed.replace(b"PRUEBA FIRMANTE", b"OTRO FIRMANTE"), pki)
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "HASH_FAILURE"
    assert report.signer == leaf  # identified before the digests
    # what was read before the digests is still reported, as Firma Perú does (increment 6)
    assert report.claimed_signing_time is not None
    assert report.scope is SignedScope.DOCUMENT
    assert report.references == ("",)


def test_altered_enveloping_content_fails_the_hash_check(pki: Pki) -> None:
    signed, _, _ = _sign(pki, packaging=XadesPackaging.ENVELOPING)
    report = _verify(signed.replace(b"PRUEBA FIRMANTE", b"OTRO FIRMANTE"), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "HASH_FAILURE")


def test_a_detached_signature_checks_the_file_it_is_given(pki: Pki) -> None:
    signed, _, _ = _sign(pki, packaging=XadesPackaging.DETACHED)
    other = _verify(signed, pki, content=CONTENT.replace(b"PRUEBA", b"OTRA"))
    assert (other.indication, other.subindication) == (Indication.TOTAL_FAILED, "HASH_FAILURE")
    missing = _verify(signed, pki)
    assert missing.indication is Indication.INDETERMINATE
    assert missing.subindication == "SIGNED_DATA_NOT_FOUND"


def test_an_altered_signed_property_fails_the_hash_check(pki: Pki) -> None:
    def later(root: Any) -> None:
        root.find(".//xades:SigningTime", NS).text = "2030-01-01T00:00:00+00:00"

    report = _verify(_edit(_sign(pki)[0], later), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "HASH_FAILURE")


def test_an_altered_signature_value_fails_the_crypto_check(pki: Pki) -> None:
    def flip(root: Any) -> None:
        value = _signature(root).find("ds:SignatureValue", NS)
        raw = bytearray(base64.b64decode(value.text))
        raw[10] ^= 0xFF
        value.text = base64.b64encode(bytes(raw)).decode()

    report = _verify(_edit(_sign(pki)[0], flip), pki)
    assert report.indication is Indication.TOTAL_FAILED
    assert report.subindication == "SIG_CRYPTO_FAILURE"


# -- the signing certificate and the format --------------------------------------------------------


def test_a_signing_certificate_that_matches_nothing_is_indeterminate(pki: Pki) -> None:
    def other_digest(root: Any) -> None:
        digest = root.find(".//xades:SigningCertificateV2//ds:DigestValue", NS)
        digest.text = base64.b64encode(b"\x00" * 32).decode()

    report = _verify(_edit(_sign(pki)[0], other_digest), pki)
    assert report.indication is Indication.INDETERMINATE
    assert report.subindication == "NO_SIGNING_CERTIFICATE_FOUND"
    assert report.signer is None


def test_unsigned_qualifying_properties_are_a_format_failure(pki: Pki) -> None:
    """The reference of type SignedProperties is what makes the signing certificate a signed
    claim: without it, the signature is not a XAdES."""

    def unreference(root: Any) -> None:
        for reference in _signature(root).findall("ds:SignedInfo/ds:Reference", NS):
            if reference.get("Type"):
                del reference.attrib["Type"]

    report = _verify(_edit(_sign(pki)[0], unreference), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "FORMAT_FAILURE")


@pytest.mark.parametrize(
    ("algorithm", "subindication"),
    [
        ("http://www.w3.org/TR/1999/REC-xslt-19991116", "FORMAT_FAILURE"),
        ("http://www.w3.org/TR/1999/REC-xpath-19991116", "FORMAT_FAILURE"),
    ],
)
def test_a_transform_outside_the_allow_list_is_refused(
    pki: Pki, algorithm: str, subindication: str
) -> None:
    """XSLT and XPath 1.0 transforms are not executed (AM-06): what is signed must be
    something berigna can show."""

    def transform(root: Any) -> None:
        reference = _signature(root).find("ds:SignedInfo/ds:Reference", NS)
        reference.find("ds:Transforms/ds:Transform", NS).set("Algorithm", algorithm)

    report = _verify(_edit(_sign(pki)[0], transform), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, subindication)


def _with_sha1_reference(pki: Pki, document: bytes = CONTENT) -> tuple[bytes, Any]:
    """``document`` signed by a software key with a SHA-1 reference, consistent: the digest
    recomputed with SHA-1 and SignedInfo signed again (ReFirma's older signatures)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed, leaf = _software_signed(pki, key)
    root = etree.fromstring(signed)
    signature = _signature(root)
    reference = signature.find("ds:SignedInfo/ds:Reference", NS)
    reference.find("ds:DigestMethod", NS).set("Algorithm", f"{DS}sha1")
    unsigned = etree.fromstring(signed)
    unsigned.remove(_signature(unsigned))
    digest = hashlib.sha1(etree.tostring(unsigned, method="c14n", with_comments=False))  # noqa: S324
    reference.find("ds:DigestValue", NS).text = base64.b64encode(digest.digest()).decode()
    signed_info = etree.tostring(signature.find("ds:SignedInfo", NS), method="c14n")
    value = key.sign(signed_info, padding.PKCS1v15(), hashes.SHA256())
    signature.find("ds:SignatureValue", NS).text = base64.b64encode(value).decode()
    return bytes(etree.tostring(root)), leaf


def test_a_weak_digest_is_a_crypto_constraints_failure(pki: Pki) -> None:
    """ACR-18: an intact signature whose reference uses SHA-1 is not accepted."""
    signed, leaf = _with_sha1_reference(pki)
    report = _verify(signed, pki, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()])
    assert report.indication is Indication.INDETERMINATE
    assert report.subindication == "CRYPTO_CONSTRAINTS_FAILURE"


def test_an_altered_document_with_a_weak_digest_is_still_a_hash_failure(pki: Pki) -> None:
    """The alteration comes first (§5.2.7): "the document was changed", not "weak
    algorithm" (review of the increment)."""
    signed, _ = _with_sha1_reference(pki)
    report = _verify(signed.replace(b"PRUEBA FIRMANTE", b"OTRO FIRMANTE"), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "HASH_FAILURE")


# -- XML Signature Wrapping (AM-06, PR-VAL-08) -----------------------------------------------------


def test_a_duplicated_identifier_is_a_format_failure(pki: Pki) -> None:
    """The classic wrapping: a second element with the Id of the signed object. berigna never
    picks "the first one"."""

    def wrap(root: Any) -> None:
        signature = _signature(root)
        target = signature.find(".//ds:Object[@Id='object']", NS)
        decoy = etree.SubElement(signature, f"{{{DS}}}Object", Id="object")
        decoy.append(etree.fromstring(b"<Declaracion><Titular>ATACANTE</Titular></Declaracion>"))
        assert target is not None

    signed, _, _ = _sign(pki, packaging=XadesPackaging.ENVELOPING)
    report = _verify(_edit(signed, wrap), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "FORMAT_FAILURE")


def test_the_same_identifier_in_lowercase_counts_as_a_duplicate(pki: Pki) -> None:
    def wrap(root: Any) -> None:
        etree.SubElement(_signature(root), f"{{{DS}}}Object", id="object").text = "otro"

    signed, _, _ = _sign(pki, packaging=XadesPackaging.ENVELOPING)
    report = _verify(_edit(signed, wrap), pki)
    assert report.subindication == "FORMAT_FAILURE"


def test_a_signature_over_part_of_the_document_says_so(pki: Pki) -> None:
    """A valid signature that covers one element: the rest of the document is not signed,
    and the report says it (SignedScope.PART) so that the interface can warn."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf("FIRMANTE PARCIAL", key=key)
    document = etree.fromstring(
        b'<Acta><Parte Id="parte">firmado</Parte><Resto>sin firmar</Resto></Acta>'
    )
    signed = XAdESSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ).sign(  # type: ignore[call-arg]  # @wraps confuses mypy (signxml 4.0.5)
        document,
        key=key,
        cert=[leaf.public_bytes(serialization.Encoding.PEM).decode()],
        reference_uri="#parte",
    )
    data = bytes(etree.tostring(signed))
    report = _verify(data, pki, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()])
    assert report.indication is Indication.TOTAL_PASSED
    assert report.scope is SignedScope.PART
    assert report.references == ("#parte",)
    changed = _verify(data.replace(b"sin firmar", b"cambiado"), pki)
    assert changed.subindication != "HASH_FAILURE"  # the unsigned part is not covered


def _software_signed(pki: Pki, key: Any, algorithm: str = "rsa-sha256") -> tuple[bytes, Any]:
    """CONTENT signed enveloped by signxml with a software key (no card): for the shapes of
    other signers, rebuilt here on purpose. Returns the document and the signer."""
    leaf = pki.leaf("FIRMANTE SOFTWARE", key=key)
    signed = XAdESSigner(
        method=methods.enveloped,
        signature_algorithm=algorithm,
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ).sign(  # type: ignore[call-arg]  # @wraps confuses mypy (signxml 4.0.5)
        etree.fromstring(CONTENT),
        key=key,
        cert=[leaf.public_bytes(serialization.Encoding.PEM).decode()],
    )
    return bytes(etree.tostring(signed)), leaf


def _filter2(signed: bytes, key: Any, filters: list[tuple[str, str]]) -> bytes:
    """``signed`` with the enveloped transform replaced by XPath Filter 2.0 ``filters``, as
    Firma Perú and DSS write it, the digest recomputed and SignedInfo signed again."""
    root = etree.fromstring(signed)
    signature = _signature(root)
    reference = signature.find("ds:SignedInfo/ds:Reference", NS)
    transforms = reference.find("ds:Transforms", NS)
    enveloped = transforms.find("ds:Transform", NS)
    filter2 = "http://www.w3.org/2002/06/xmldsig-filter2"
    replacement = etree.Element(f"{{{DS}}}Transform", Algorithm=filter2)
    for kind, expression in filters:
        xpath = etree.SubElement(
            replacement, f"{{{filter2}}}XPath", Filter=kind, nsmap={"dsig-filter2": filter2}
        )
        xpath.text = expression
    transforms.replace(enveloped, replacement)
    unsigned = etree.fromstring(signed)
    for element in unsigned.xpath("//*[local-name()='Signature' or local-name()='Texto']"):
        if element.tag != f"{{{DS}}}Signature" and ("subtract", "//Texto") not in filters:
            continue
        element.getparent().remove(element)
    digest = hashlib.sha256(etree.tostring(unsigned, method="c14n", with_comments=False))
    reference.find("ds:DigestValue", NS).text = base64.b64encode(digest.digest()).decode()
    signed_info = etree.tostring(signature.find("ds:SignedInfo", NS), method="c14n")
    value = key.sign(signed_info, padding.PKCS1v15(), hashes.SHA256())
    signature.find("ds:SignatureValue", NS).text = base64.b64encode(value).decode()
    return bytes(etree.tostring(root))


def test_xpath_filter2_subtract_of_the_signatures_is_supported(pki: Pki) -> None:
    """The shape of Firma Perú and DSS (PR-INT-05): URI="" and XPath Filter 2.0 subtracting
    every ds:Signature. It covers the whole document."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed, leaf = _software_signed(pki, key)
    data = _filter2(signed, key, [("subtract", "/descendant::ds:Signature")])
    report = _verify(data, pki, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()])
    assert (report.indication, report.subindication) == (Indication.TOTAL_PASSED, None)
    assert report.scope is SignedScope.DOCUMENT
    changed = _verify(data.replace(b"PRUEBA FIRMANTE", b"OTRO"), pki)
    assert changed.subindication == "HASH_FAILURE"


def test_xpath_filter2_that_subtracts_content_signs_only_a_part(pki: Pki) -> None:
    """AM-06: a filter that also removes an element of the document. The signature is valid,
    but the removed element is not signed, and the report says so."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed, leaf = _software_signed(pki, key)
    data = _filter2(
        signed, key, [("subtract", "/descendant::ds:Signature"), ("subtract", "//Texto")]
    )
    report = _verify(data, pki, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()])
    assert report.indication is Indication.TOTAL_PASSED
    assert report.scope is SignedScope.PART


@pytest.mark.parametrize("kind", ["intersect", "union"])
def test_xpath_filter2_that_selects_is_refused(pki: Pki, kind: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed, _ = _software_signed(pki, key)
    report = _verify(_filter2(signed, key, [(kind, "//Titular")]), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "FORMAT_FAILURE")


def test_an_ecdsa_signature_verifies(pki: Pki) -> None:
    """XMLDSig ECDSA carries r and s concatenated, not DER: berigna converts it."""
    key = ec.generate_private_key(ec.SECP256R1())
    signed, leaf = _software_signed(pki, key, "ecdsa-sha256")
    report = _verify(signed, pki, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()])
    assert (report.indication, report.subindication) == (Indication.TOTAL_PASSED, None)
    assert report.signer == leaf


def test_an_xpointer_reference_is_refused(pki: Pki) -> None:
    def xpointer(root: Any) -> None:
        _signature(root).find("ds:SignedInfo/ds:Reference", NS).set("URI", "#xpointer(/)")

    report = _verify(_edit(_sign(pki)[0], xpointer), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "FORMAT_FAILURE")


# -- findings of the review of the increment ----------------------------------------------------


def test_text_added_after_the_signature_is_not_signed(pki: Pki) -> None:
    """lxml drops the text after a removed element: the enveloped transform must keep it,
    or text appended after </ds:Signature> would pass as signed."""

    def append(root: Any) -> None:
        _signature(root).tail = "PAGAR S/ 10000"

    report = _verify(_edit(_sign(pki)[0], append), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "HASH_FAILURE")


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", b'<b xml:id="i" xml:lang="es">t</b>'),
        ("http://www.w3.org/2006/12/xml-c14n11", b'<b xml:lang="es">t</b>'),
        ("http://www.w3.org/2001/10/xml-exc-c14n#", b"<b>t</b>"),
    ],
)
def test_a_subset_inherits_the_xml_attributes(algorithm: str, expected: bytes) -> None:
    """C14N 1.0 inherits every xml: attribute of the ancestors, 1.1 only xml:lang and
    xml:space, the exclusive one none; lxml inherits none by itself (Santuario does)."""
    from berigna.core.validation import xades as module

    root = etree.fromstring(b'<a xml:lang="es" xml:id="i"><b>t</b></a>')
    assert module._c14n_of(root[0], algorithm) == expected


def test_c14n11_under_an_xml_base_is_refused() -> None:
    from berigna.core.validation import xades as module

    root = etree.fromstring(b'<a xml:base="http://ejemplo/"><b>t</b></a>')
    with pytest.raises(module._Result):
        module._c14n_of(root[0], "http://www.w3.org/2006/12/xml-c14n11")


def test_a_fake_signature_that_wraps_content_makes_the_scope_partial(pki: Pki) -> None:
    """AM-06: with the Firma Perú filter (subtract every ds:Signature), a clause wrapped in a
    fake ds:Signature is not signed. The real signature stays valid but says PART; the fake
    one is a format failure of its own."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed, leaf = _software_signed(pki, key)
    data = _filter2(signed, key, [("subtract", "/descendant::ds:Signature")])

    def inject(root: Any) -> None:
        fake = etree.SubElement(root, f"{{{DS}}}Signature")
        etree.SubElement(fake, "Clausula").text = "El firmante renuncia a todo"

    reports = verify_xades(
        _edit(data, inject),
        pki.store,
        online=False,
        ocsp_responses=[pki.ocsp(leaf)],
        crls=[pki.arl()],
    ).signatures
    real, fake = reports
    assert real.indication is Indication.TOTAL_PASSED
    assert real.scope is SignedScope.PART
    assert fake.subindication == "FORMAT_FAILURE"


def test_several_external_references_are_not_checked_against_one_file(pki: Pki) -> None:
    def second(root: Any) -> None:
        signed_info = root.find("ds:SignedInfo", NS)
        extra = copy.deepcopy(signed_info.find("ds:Reference", NS))
        extra.set("URI", "anexo.pdf")
        signed_info.append(extra)

    signed, _, _ = _sign(pki, packaging=XadesPackaging.DETACHED)
    report = _verify(_edit(signed, second), pki, content=CONTENT)
    assert report.indication is Indication.INDETERMINATE
    assert report.subindication == "SIGNED_DATA_NOT_FOUND"


def test_a_broken_signature_timestamp_fails_only_the_timestamp(pki: Pki) -> None:
    def empty(root: Any) -> None:
        stamp = root.find(".//xades:SignatureTimeStamp", NS)
        stamp.remove(stamp.find("xades:EncapsulatedTimeStamp", NS))

    report = _verify(_edit(_sign(pki, SignatureLevel.B_T)[0], empty), pki)
    assert report.subindication == "TRY_LATER"  # the signature itself, as without the stamp
    assert report.timestamp is not None
    assert report.timestamp.subindication == "FORMAT_FAILURE"


@pytest.mark.parametrize(
    ("packaging", "scope"),
    [
        (XadesPackaging.ENVELOPING, SignedScope.OBJECT),
        (XadesPackaging.DETACHED, SignedScope.EXTERNAL),
    ],
)
def test_a_signature_wrapped_in_a_container_keeps_its_packaging(
    pki: Pki, packaging: XadesPackaging, scope: SignedScope
) -> None:
    """The packaging comes from what the references point at, not from the position."""
    signed, _, _ = _sign(pki, packaging=packaging)
    container = etree.Element("Lote")
    container.append(etree.fromstring(signed))
    data = bytes(etree.tostring(container))
    content = CONTENT if packaging is XadesPackaging.DETACHED else None
    report = _verify(data, pki, content=content)
    assert report.packaging is packaging
    assert report.scope is scope


@pytest.mark.parametrize("level", [SignatureLevel.B_B, SignatureLevel.B_LTA])
def test_berigna_signs_a_root_with_xml_attributes(pki: Pki, level: SignatureLevel) -> None:
    """The enveloped signature of a root with xml:lang came out invalid, also in DSS:
    berigna now signs with exclusive C14N, where nothing is inherited (2026-11-02)."""
    document = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Declaracion xml:lang="es-PE" xml:space="preserve" xml:base="http://ejemplo/">'
        b"<Titular>PRUEBA FIRMANTE</Titular></Declaracion>"
    )
    signed, leaf, tsa = _sign(pki, level, content=document)
    report = _verify(signed, pki, ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)], crls=[pki.arl()])
    assert (report.indication, report.subindication) == (Indication.TOTAL_PASSED, None)
    assert all(a.indication is Indication.TOTAL_PASSED for a in report.archive_timestamps)


def test_a_prefix_used_only_in_a_value_cannot_be_rebound(pki: Pki) -> None:
    """The data object is digested with C14N 1.0: a namespace declaration used only inside a
    value (xsi:type="ns:Tipo", as in UBL) is covered, and rebinding it after signing breaks
    the signature (review of the fix of 2026-11-02)."""
    document = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Declaracion xmlns:ns="urn:berigna:prueba" '
        b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        b'<Titular xsi:type="ns:Tipo">PRUEBA FIRMANTE</Titular></Declaracion>'
    )
    signed, _, _ = _sign(pki, content=document)
    rebound = signed.replace(b'xmlns:ns="urn:berigna:prueba"', b'xmlns:ns="urn:atacante"')
    assert rebound != signed
    report = _verify(rebound, pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "HASH_FAILURE")


# -- revocation and time (PR-VAL-02, PR-VAL-03, RF-056) --------------------------------------------


def test_a_revoked_signer_is_reported(pki: Pki) -> None:
    signed, leaf, _ = _sign(pki)
    report = _verify(signed, pki, ocsp_responses=[pki.ocsp(leaf, revoked=True)], crls=[pki.arl()])
    assert report.indication is Indication.INDETERMINATE
    assert report.subindication == "REVOKED_NO_POE"


def test_a_signer_outside_the_trust_store_is_indeterminate(pki: Pki) -> None:
    signed, _, _ = _sign(build_pki())
    assert _verify(signed, pki).indication is Indication.INDETERMINATE


def test_an_expired_certificate_without_timestamp_is_indeterminate(pki: Pki) -> None:
    signed, _, _ = _sign(pki, leaf_days=(-10, 1))
    report = _verify(signed, pki, moment=NOW + dt.timedelta(days=400))
    assert report.indication is Indication.INDETERMINATE


def test_an_expired_certificate_passes_with_proof_of_existence(pki: Pki) -> None:
    """RF-056: the signature time-stamp proves that the signature existed while the
    certificate was valid."""
    signed, _, tsa = _sign(pki, SignatureLevel.B_T, leaf_days=(-10, 1))
    moment = NOW + dt.timedelta(days=3)
    report = _verify(
        signed, pki, moment=moment, ocsp_responses=[pki.ocsp(tsa, at=moment)], crls=[pki.arl()]
    )
    assert report.indication is Indication.TOTAL_PASSED
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.TOTAL_PASSED


def test_a_certificate_with_an_impossible_version_is_a_format_failure(pki: Pki) -> None:
    """Found by fuzzing: cryptography raises InvalidVersion, not ValueError (AM-05)."""

    def version_10(root: Any) -> None:
        element = root.find(".//ds:X509Certificate", NS)
        der = bytearray(base64.b64decode(element.text))
        der[der.index(bytes.fromhex("a003020102")) + 4] = 10  # [0] EXPLICIT INTEGER 2 -> 10
        element.text = base64.b64encode(bytes(der)).decode()

    report = _verify(_edit(_sign(pki)[0], version_10), pki)
    assert (report.indication, report.subindication) == (Indication.TOTAL_FAILED, "FORMAT_FAILURE")


def test_a_timestamp_with_an_unknown_digest_is_a_format_failure(pki: Pki) -> None:
    """Found by fuzzing: pyHanko looks the digest of the token up with getattr and raises
    AttributeError for an OID it does not know. The time-stamp is the one that fails."""

    def unknown_digest(root: Any) -> None:
        element = root.find(".//xades:SignatureTimeStamp/xades:EncapsulatedTimeStamp", NS)
        info = cms.ContentInfo.load(base64.b64decode(element.text))
        info["content"]["signer_infos"][0]["digest_algorithm"]["algorithm"] = "2.16.840.15.1"
        element.text = base64.b64encode(info.dump(force=True)).decode()

    signed, leaf, tsa = _sign(pki, SignatureLevel.B_T)
    report = _verify(
        _edit(signed, unknown_digest),
        pki,
        ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
        crls=[pki.arl()],
    )
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.TOTAL_FAILED
    assert report.timestamp.subindication == "FORMAT_FAILURE"


# -- reading errors --------------------------------------------------------------------------------


def test_bytes_that_are_not_xml_are_an_error(pki: Pki) -> None:
    with pytest.raises(UnreadableDocumentError) as info:
        verify_xades(b"%PDF-1.7", pki.store, online=False)
    assert info.value.code == "ERR-401"


def test_a_document_with_a_dtd_is_an_error(pki: Pki) -> None:
    """Entities would change what is digested; DSS refuses the DOCTYPE too."""
    document = b'<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>'
    with pytest.raises(UnreadableDocumentError):
        verify_xades(document, pki.store, online=False)


def test_a_document_without_signature_is_an_error(pki: Pki) -> None:
    with pytest.raises(UnreadableSignatureError) as info:
        verify_xades(CONTENT, pki.store, online=False)
    assert info.value.code == "ERR-402"


# -- properties ------------------------------------------------------------------------------------

_NAMES = st.from_regex(r"[A-Za-z][A-Za-z0-9]{0,8}", fullmatch=True)
_TEXT = st.text(
    alphabet=st.characters(codec="utf-8", exclude_categories=("Cs", "Cc"), exclude_characters="￾￿"),
    max_size=20,
)


@st.composite
def _documents(draw: st.DrawFn) -> bytes:
    """Small XML documents: nested elements, attributes, text, comments."""

    def element(depth: int) -> Any:
        node = etree.Element(draw(_NAMES))
        for name in draw(st.lists(_NAMES, max_size=2, unique=True)):
            node.set(name, draw(_TEXT))
        node.text = draw(_TEXT)
        if draw(st.booleans()):
            node.append(etree.Comment(draw(_TEXT).replace("-", "_")))
        if depth < 2:
            for _ in range(draw(st.integers(0, 3))):
                node.append(element(depth + 1))
        return node

    return bytes(etree.tostring(element(0), xml_declaration=True, encoding="UTF-8"))


_PROPERTY = settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)


@_PROPERTY
@given(document=_documents(), packaging=st.sampled_from(list(XadesPackaging)))
def test_any_document_signed_by_berigna_verifies(
    pki: Pki, document: bytes, packaging: XadesPackaging
) -> None:
    """Signing and verifying agree on any document (round trip, increment 5)."""
    signed, leaf, _ = _sign(pki, packaging=packaging, content=document)
    report = _verify(
        signed,
        pki,
        content=document if packaging is XadesPackaging.DETACHED else None,
        ocsp_responses=[pki.ocsp(leaf)],
        crls=[pki.arl()],
    )
    assert (report.indication, report.subindication) == (Indication.TOTAL_PASSED, None)


@_PROPERTY
@given(document=_documents(), position=st.integers(min_value=0), byte=st.integers(0, 255))
def test_any_mutation_is_a_result_or_a_reading_error(
    pki: Pki, document: bytes, position: int, byte: int
) -> None:
    """A signed document with any byte changed: never an unexpected exception (AM-05), and
    never a TOTAL-PASSED unless the change fell outside what is signed: the canonical
    document without comments, whitespace and unsigned properties must be the same (a
    comment, the whitespace between attributes or inside the base64 values, or a time-stamp
    or a value of the unsigned properties, which get their own report, may change)."""
    signed, leaf, _ = _sign(pki, content=document)
    index = position % len(signed)
    mutated = signed[:index] + bytes([byte]) + signed[index + 1 :]
    try:
        reports = verify_xades(
            mutated,
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],
            crls=[pki.arl()],
        ).signatures
    except (UnreadableDocumentError, UnreadableSignatureError):
        return
    for report in reports:
        assert isinstance(report.indication, Indication)
        if report.indication is Indication.TOTAL_PASSED:
            assert _canonical(mutated) == _canonical(signed)


def _canonical(document: bytes) -> bytes:
    tree = etree.fromstring(document, etree.XMLParser(resolve_entities=False))
    for unsigned in tree.iter(f"{{{XADES}}}UnsignedProperties"):
        unsigned.getparent().remove(unsigned)
    return b"".join(etree.tostring(tree, method="c14n", with_comments=False).split())
