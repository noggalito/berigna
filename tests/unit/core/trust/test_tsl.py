# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""INDECOPI trusted list (ADR-0014): verification, reading and use as trust anchors."""

import datetime as dt
import hashlib
from pathlib import Path
from typing import Any

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from lxml import etree

from berigna.core.errors import TrustStoreIntegrityError, TslError, TslExpiredError
from berigna.core.trust import TrustedCertificate, TrustStore
from berigna.core.trust import tsl as tsl_module
from berigna.core.trust.tsl import (
    TSL_ROOT_SHA256,
    describe,
    extend_store,
    fetch_tsl,
    load_tsl,
    tsl_root,
)
from support.pki import NOW, Pki, build_pki
from support.tsl import (
    WITHDRAWN,
    Service,
    TslContent,
    TslPki,
    build_tsl,
    build_tsl_pki,
    sign_tsl,
    unsigned_tsl,
)

DATA = Path(__file__).resolve().parents[3] / "data" / "tsl"
REAL = (DATA / "tsl-pe-2026-08-10.xml").read_bytes()
REAL_CRL = (DATA / "indecopi-tsl-2026-10-27.crl").read_bytes()
REAL_MOMENT = dt.datetime(2026, 10, 28, 12, tzinfo=dt.UTC)  # inside the CRL's validity


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@pytest.fixture(scope="module")
def tsl_pki() -> TslPki:
    return build_tsl_pki()


def _sha256(certificate: x509.Certificate) -> str:
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


# -- the real list published by INDECOPI (2026-08-10, sequence 25) ------------------------------


def test_real_list_verifies_against_the_pinned_root() -> None:
    trusted = load_tsl(REAL, moment=REAL_MOMENT, signer_crl=REAL_CRL)
    assert trusted.sequence_number == 25
    assert trusted.operator.startswith("INSTITUTO NACIONAL DE DEFENSA DE LA COMPETENCIA")
    assert trusted.next_update == dt.datetime(2027, 2, 10, 11, 10, 31, 312000, tzinfo=dt.UTC)
    assert "TSL Suscriptor" in trusted.signer.subject.rfc4514_string()
    fingerprints = {_sha256(c) for c in trusted.ca_certificates()}
    bundled = {e.sha256 for e in TrustStore.load_bundled().entries if e.role == "root"}
    assert bundled <= fingerprints  # ROOT 3 and ROOT 5 are in the list
    assert any("ROOT 6" in c.subject.rfc4514_string() for c in trusted.ca_certificates())
    assert describe(trusted).startswith("TSL 25 issued 2026-08-10")


def test_real_list_tampered_is_refused() -> None:
    with pytest.raises(TslError, match="does not verify"):
        load_tsl(REAL.replace(b"WISEKEY", b"WISEKEZ", 1), moment=REAL_MOMENT)


def test_real_list_after_its_next_update_is_refused() -> None:
    with pytest.raises(TslExpiredError) as info:
        load_tsl(REAL, moment=dt.datetime(2027, 3, 1, tzinfo=dt.UTC))
    assert info.value.code == "ERR-204"


def test_older_list_than_the_one_accepted_is_refused() -> None:
    with pytest.raises(TslError, match="older"):
        load_tsl(REAL, moment=REAL_MOMENT, minimum_sequence=26)


def test_out_of_date_signer_crl_is_refused() -> None:
    with pytest.raises(TslError, match="out of date"):
        load_tsl(REAL, moment=dt.datetime(2026, 10, 30, tzinfo=dt.UTC), signer_crl=REAL_CRL)


def test_pinned_root(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _sha256(tsl_root()) == TSL_ROOT_SHA256
    monkeypatch.setattr(tsl_module, "TSL_ROOT_SHA256", "00" * 32)
    with pytest.raises(TrustStoreIntegrityError):
        tsl_root()


# -- synthetic lists: what is trusted ---------------------------------------------------------


def test_accepted_ca_certificates_extend_the_store(pki: Pki, tsl_pki: TslPki) -> None:
    leaf = pki.leaf("NO ES CA")
    other = build_pki()
    content = TslContent(
        services=[
            Service(pki.root),
            Service(pki.ca),
            Service(pki.ca),  # duplicate entry
            Service(leaf),  # not a CA: never an anchor
            Service(other.root, status=WITHDRAWN),  # withdrawn service
        ]
    )
    trusted = load_tsl(build_tsl(tsl_pki, content), root=tsl_pki.root, signer_crl=tsl_pki.crl())
    assert [s.accepted for s in trusted.services] == [True, True, True, True, False]
    assert trusted.services[0].service_type == "CA/QC"
    assert {_sha256(c) for c in trusted.ca_certificates()} == {_sha256(pki.root), _sha256(pki.ca)}
    base = TrustStore([TrustedCertificate(pki.root, "root", "IOFE")])
    store = extend_store(base, trusted)
    assert [(e.role, e.hierarchy) for e in store.entries] == [
        ("root", "IOFE"),  # already known: not added twice
        ("intermediate", "TSL"),
    ]


def test_signature_from_a_trusted_list_root_verifies_a_document(pki: Pki, tsl_pki: TslPki) -> None:
    """End to end: an anchor that only the trusted list provides makes a signature valid."""
    from berigna.core.formats.pades import SignatureLevel, sign_pdf_pades
    from berigna.core.token.dnie_v2 import DnieV2Token
    from berigna.core.token.pin import Pin
    from berigna.core.validation import Indication, signing_validation_context, verify_pdf
    from support.cards import make_card
    from support.pki import minimal_pdf
    from support.tsa import make_timestamper

    card, leaf = make_card(pki, "FIRMANTE TSL")
    stamper, tsa = make_timestamper(pki)
    context = signing_validation_context(
        pki.store, online=False, ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)], crls=[pki.arl()]
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        signed = sign_pdf_pades(
            minimal_pdf(),
            token,
            (pki.root, pki.ca, leaf),
            level=SignatureLevel.B_LT,
            timestamper=stamper,
            validation_context=context,
        ).data
    trusted = load_tsl(
        build_tsl(tsl_pki, TslContent(services=[Service(pki.root)])), root=tsl_pki.root
    )
    assert verify_pdf(signed, TrustStore([]), online=False).signatures[0].indication is (
        Indication.INDETERMINATE
    )
    store = extend_store(TrustStore([]), trusted)
    assert verify_pdf(signed, store, online=False).signatures[0].indication is (
        Indication.TOTAL_PASSED
    )


# -- synthetic lists: what is refused ---------------------------------------------------------


def test_list_signed_under_another_root_is_refused(tsl_pki: TslPki) -> None:
    impostor = build_tsl_pki()
    with pytest.raises(TslError, match="not signed under"):
        load_tsl(build_tsl(impostor), root=tsl_pki.root)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"signer_days": (-10, -1)}, "not valid at"),
        ({"signer_usage": x509.KeyUsage(*([False] * 5), True, True, False, False)}, "may not sign"),
    ],
    ids=["firmante-vencido", "firmante-sin-uso-de-firma"],
)
def test_unfit_signer_is_refused(kwargs: dict[str, Any], message: str) -> None:
    unfit = build_tsl_pki(**kwargs)
    with pytest.raises(TslError, match=message):
        load_tsl(build_tsl(unfit), root=unfit.root)


def test_signer_without_key_usage_is_refused() -> None:
    """The real INDECOPI signer states digitalSignature; a signer that states nothing is refused."""
    plain = build_tsl_pki(key_usage=False)
    with pytest.raises(TslError, match="does not state its key usage"):
        load_tsl(build_tsl(plain), root=plain.root)


def test_revoked_signer_is_refused(tsl_pki: TslPki) -> None:
    with pytest.raises(TslError, match="revoked"):
        load_tsl(build_tsl(tsl_pki), root=tsl_pki.root, signer_crl=tsl_pki.crl(revoked=True))


def test_signer_crl_must_come_from_the_root(tsl_pki: TslPki) -> None:
    forged = tsl_pki.crl(key=build_tsl_pki().root_key)
    with pytest.raises(TslError, match="not signed by its root"):
        load_tsl(build_tsl(tsl_pki), root=tsl_pki.root, signer_crl=forged)
    with pytest.raises(TslError, match="unreadable CRL"):
        load_tsl(build_tsl(tsl_pki), root=tsl_pki.root, signer_crl=b"no es una CRL")


def test_pem_crl_is_read(tsl_pki: TslPki) -> None:
    pem = x509.load_der_x509_crl(tsl_pki.crl()).public_bytes(serialization.Encoding.PEM)
    assert load_tsl(build_tsl(tsl_pki), root=tsl_pki.root, signer_crl=pem).sequence_number == 7


def test_signature_wrapping_reads_only_the_signed_list(pki: Pki, tsl_pki: TslPki) -> None:
    """A signature over another element does not vouch for the list around it."""
    root = unsigned_tsl(TslContent(services=[Service(pki.root)]))
    inner = etree.SubElement(root, "{http://uri.etsi.org/02231/v2#}Extension")
    inner.set("Id", "otra-cosa")
    with pytest.raises(TslError, match="covers the whole list"):
        load_tsl(sign_tsl(root, tsl_pki, reference_uri="#otra-cosa"), root=tsl_pki.root)


def test_weak_digest_on_the_list_is_refused(
    tsl_pki: TslPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tsl_module, "_STRONG_DIGESTS", set())
    with pytest.raises(TslError, match="SHA-256 or stronger"):
        load_tsl(build_tsl(tsl_pki), root=tsl_pki.root)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"<no-cierra", "not well-formed"),
        (b"<otra xmlns='urn:x'/>", "not an ETSI trusted list"),
        (
            b"<tsl:TrustServiceStatusList xmlns:tsl='http://uri.etsi.org/02231/v2#'/>",
            "exactly one enveloped signature",
        ),
    ],
    ids=["xml-roto", "otro-documento", "sin-firma"],
)
def test_malformed_input_is_refused(data: bytes, message: str, tsl_pki: TslPki) -> None:
    with pytest.raises(TslError, match=message):
        load_tsl(data, root=tsl_pki.root)


def test_oversized_list_is_refused(tsl_pki: TslPki, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tsl_module, "MAX_TSL_SIZE", 10)
    with pytest.raises(TslError, match="larger than"):
        load_tsl(build_tsl(tsl_pki), root=tsl_pki.root)


def test_signature_without_references_is_refused(tsl_pki: TslPki) -> None:
    ds = "http://www.w3.org/2000/09/xmldsig#"
    document = etree.fromstring(build_tsl(tsl_pki))
    for reference in document.findall(f".//{{{ds}}}Reference"):
        reference.getparent().remove(reference)
    with pytest.raises(TslError, match="number of signature references"):
        load_tsl(etree.tostring(document), root=tsl_pki.root)


def test_signer_certificate_problems(tsl_pki: TslPki) -> None:
    signed = build_tsl(tsl_pki)
    ds = "http://www.w3.org/2000/09/xmldsig#"
    document = etree.fromstring(signed)
    certificate = document.find(f".//{{{ds}}}X509Certificate")
    certificate.text = "AAAA"
    with pytest.raises(TslError, match="unreadable signer certificate"):
        load_tsl(etree.tostring(document), root=tsl_pki.root)
    certificate.getparent().remove(certificate)
    with pytest.raises(TslError, match="does not carry"):
        load_tsl(etree.tostring(document), root=tsl_pki.root)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (TslContent(with_scheme=False), "no scheme information"),
        (TslContent(issued="ayer"), "unreadable scheme information"),
    ],
    ids=["sin-esquema", "fecha-ilegible"],
)
def test_bad_scheme_information(content: TslContent, message: str, tsl_pki: TslPki) -> None:
    with pytest.raises(TslError, match=message):
        load_tsl(build_tsl(tsl_pki, content), root=tsl_pki.root)


def test_naive_dates_are_taken_as_utc_and_bad_certificates_are_skipped(
    pki: Pki, tsl_pki: TslPki
) -> None:
    content = TslContent(services=[Service(pki.root)], next_update="2099-01-01T00:00:00")
    root = unsigned_tsl(content)
    bad = root.find(".//{http://uri.etsi.org/02231/v2#}X509Certificate")
    bad.text = "AAAA"
    trusted = load_tsl(sign_tsl(root, tsl_pki), root=tsl_pki.root)
    assert trusted.next_update.tzinfo is dt.UTC
    assert trusted.services[0].certificates == ()


# -- download ---------------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status_code = status
        self.body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def iter_content(self, size: int) -> list[bytes]:
        return [self.body[i : i + size] for i in range(0, len(self.body), size)] or [b""]


def test_download_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(TslError, match="non-HTTPS"):
        tsl_module._download("http://iofe.example/tsl.xml", 1, 100)
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(404, b""))
    with pytest.raises(TslError, match="HTTP 404"):
        tsl_module._download("https://iofe.example/tsl.xml", 1, 100)
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, b"x" * 200))
    with pytest.raises(TslError, match="larger than"):
        tsl_module._download("https://iofe.example/tsl.xml", 1, 100)

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse(200, b"lista"))
    assert tsl_module._download("https://iofe.example/tsl.xml", 1, 100) == b"lista"

    def unreachable(*args: object, **kwargs: object) -> None:
        raise requests.ConnectionError("no route")

    monkeypatch.setattr(requests, "get", unreachable)
    with pytest.raises(TslError, match="cannot download"):
        tsl_module._download("https://iofe.example/tsl.xml", 1, 100)


def test_fetch_downloads_the_list_and_the_signer_crl(
    tsl_pki: TslPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = build_tsl(tsl_pki)
    asked: list[str] = []

    def download(url: str, timeout: float, limit: int) -> bytes:
        asked.append(url)
        return listing if url.endswith(".xml") else tsl_pki.crl()

    monkeypatch.setattr(tsl_module, "_download", download)
    monkeypatch.setattr(tsl_module, "tsl_root", lambda: tsl_pki.root)
    trusted, _data = fetch_tsl(url="https://iofe.example/tsl.xml")
    assert trusted.sequence_number == 7
    assert asked == ["https://iofe.example/tsl.xml", "https://crl.example/tsl.crl"]


def test_fetch_needs_a_crl_address(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.hazmat.primitives import hashes

    plain = build_tsl_pki()
    no_cdp = (
        x509.CertificateBuilder()
        .subject_name(plain.signer.subject)
        .issuer_name(plain.root.subject)
        .public_key(plain.signer_key.public_key())
        .serial_number(plain.signer.serial_number)
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=1))
        .sign(plain.root_key, hashes.SHA256())
    )
    listing = build_tsl(TslPki(plain.root, plain.root_key, no_cdp, plain.signer_key))
    monkeypatch.setattr(tsl_module, "_download", lambda url, timeout, limit: listing)
    with pytest.raises(TslError, match="no HTTPS CRL"):
        fetch_tsl()


def test_fetch_tries_every_crl_distribution_point(monkeypatch: pytest.MonkeyPatch) -> None:
    mirrors = build_tsl_pki(
        crl_urls=("https://caido.example/tsl.crl", "https://espejo.example/tsl.crl")
    )
    listing = build_tsl(mirrors)
    asked: list[str] = []

    def download(url: str, timeout: float, limit: int) -> bytes:
        asked.append(url)
        if url.endswith(".xml"):
            return listing
        if "caido" in url:
            raise TslError("unreachable")
        return mirrors.crl()

    monkeypatch.setattr(tsl_module, "_download", download)
    monkeypatch.setattr(tsl_module, "tsl_root", lambda: mirrors.root)
    assert fetch_tsl(url="https://iofe.example/tsl.xml")[0].sequence_number == 7
    assert asked[1:] == ["https://caido.example/tsl.crl", "https://espejo.example/tsl.crl"]

    def nothing_answers(url: str, timeout: float, limit: int) -> bytes:
        if url.endswith(".xml"):
            return listing
        raise TslError(f"{url} unreachable")

    monkeypatch.setattr(tsl_module, "_download", nothing_answers)
    with pytest.raises(TslError, match=r"espejo\.example"):
        fetch_tsl(url="https://iofe.example/tsl.xml")
