# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Machine-readable verification report (RF-054)."""

import datetime as dt
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.xades import XadesPackaging
from berigna.core.report.json_report import SCHEMA, dumps, report_data
from berigna.core.trust import TrustedCertificate, TrustStore
from berigna.core.validation import (
    CadesSignatureReport,
    CadesVerification,
    Indication,
    Modifications,
    PdfSignatureReport,
    PdfVerification,
    SignedScope,
    TimestampReport,
    XadesSignatureReport,
    XadesVerification,
)
from support.pki import NOW


def _dnie_like(serial: str | None) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, "PEREZ QUISPE JUAN")]
    if serial is not None:
        attributes.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, serial))
    name = x509.Name(attributes)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST CA")]))
        .public_key(key.public_key())
        .serial_number(0x1A2B)
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def _verification(signer: x509.Certificate | None) -> PdfVerification:
    stamp = TimestampReport(Indication.TOTAL_PASSED, None, NOW, signer, None)
    signature = PdfSignatureReport(
        field_name="FirmaBerigna1",
        indication=Indication.TOTAL_PASSED,
        subindication=None,
        signer=signer,
        claimed_signing_time=NOW,
        subfilter="/ETSI.CAdES.detached",
        covers_whole_document=False,
        modifications=Modifications.LTA_UPDATES,
        signed_revision_length=1234,
        timestamp=stamp,
    )
    document_stamp = TimestampReport(Indication.TOTAL_PASSED, None, NOW, None, "SelloBerigna1")
    return PdfVerification((signature,), (document_stamp,), NOW)


def test_report_structure() -> None:
    signer = _dnie_like("PNOPE-12345678")
    store = TrustStore([TrustedCertificate(signer, "root", "usuario", user_added=True)])
    report = report_data(
        _verification(signer), file_name="contrato.pdf", file_sha256="ab" * 32, store=store
    )
    assert report["schema"] == SCHEMA
    assert report["validated_at"].endswith("Z")
    assert report["languages"] == ["es_PE", "quz_PE"]
    assert report["file"] == {"name": "contrato.pdf", "sha256": "ab" * 32}
    assert report["trust_store"] == {"anchors": 1, "user_anchors": True}
    [signature] = report["signatures"]
    assert signature["signer"] == {
        "name": "PEREZ QUISPE JUAN",
        "id_masked": "****5678",  # never the full national identity number
        "cert_serial": "1a2b",
        "issuer": "CN=TEST CA",
    }
    assert signature["indication"] == "TOTAL-PASSED"
    assert signature["sub_indication"] is None
    assert signature["modifications_after"] == "lta-updates"
    assert signature["signed_revision_length"] == 1234
    assert signature["signing_time"]["timestamp"]["tsa"] == "PEREZ QUISPE JUAN"
    assert signature["explanation"]["es_PE"].startswith("La firma es válida.")
    assert signature["explanation"]["quz_PE"].startswith("Firmaqa chiqaqmi.")
    [stamp] = report["document_timestamps"]
    assert stamp["id"] == "SelloBerigna1"
    assert stamp["tsa"] is None
    assert stamp["explanation"]["es_PE"].startswith("La firma es válida. Sello de tiempo")


def test_signer_without_identity_number_and_damaged_signature() -> None:
    signer = _dnie_like(None)
    report = report_data(
        _verification(signer), file_name="a.pdf", file_sha256="00", store=TrustStore([])
    )
    assert report["signatures"][0]["signer"]["id_masked"] is None
    failed = PdfVerification(
        (
            PdfSignatureReport(
                "Firma",
                Indication.TOTAL_FAILED,
                "FORMAT_FAILURE",
                None,
                None,
                "",
                False,
                Modifications.OTHER,
                0,
            ),
        ),
        (),
        NOW,
    )
    [signature] = report_data(failed, file_name="a.pdf", file_sha256="00", store=TrustStore([]))[
        "signatures"
    ]
    assert signature["signer"] is None
    assert signature["signing_time"] == {"claimed": None, "timestamp": None}


def test_dumps_is_valid_utf8_json() -> None:
    report = report_data(
        _verification(_dnie_like("PNOPE-12345678")),
        file_name="contraseña.pdf",
        file_sha256="00",
        store=TrustStore([]),
    )
    text = dumps(report)
    assert "contraseña" in text  # not escaped
    assert json.loads(text) == report


def _xades_report(scope: SignedScope | None) -> XadesSignatureReport:
    archive = TimestampReport(Indication.TOTAL_PASSED, None, NOW, None, None)
    return XadesSignatureReport(
        packaging=XadesPackaging.DETACHED,
        indication=Indication.TOTAL_PASSED,
        subindication=None,
        signer=_dnie_like("PNOPE-12345678"),
        claimed_signing_time=NOW,
        timestamp=None,
        archive_timestamps=(archive,),
        scope=scope,
        references=("acta.xml",),
    )


def test_report_of_cades_and_xades() -> None:
    """RF-054 for CAdES and XAdES: the packaging, what was signed (AM-06), the archive
    time-stamps and the file a detached signature signs."""
    store = TrustStore([])
    xades = XadesVerification((_xades_report(SignedScope.EXTERNAL),), NOW)
    report = report_data(
        xades,
        file_name="acta.xml.xsig",
        file_sha256="ab" * 32,
        store=store,
        signed_file=("acta.xml", "cd" * 32),
    )
    assert report["signed_file"] == {"name": "acta.xml", "sha256": "cd" * 32}
    assert report["document_timestamps"] == []
    [signature] = report["signatures"]
    assert (signature["id"], signature["format"], signature["packaging"]) == (
        None,
        "XAdES",
        "detached",
    )
    assert (signature["scope"], signature["references"]) == ("external", ["acta.xml"])
    assert signature["archive_timestamps"][0]["indication"] == "TOTAL-PASSED"
    assert signature["explanation"]["es_PE"].endswith(
        "El documento no se ha modificado desde que se firmó. La firma cubre un archivo aparte."
    )

    cades = CadesVerification(
        (
            CadesSignatureReport(
                packaging=CadesPackaging.ENVELOPING,
                indication=Indication.TOTAL_FAILED,
                subindication="HASH_FAILURE",
                signer=_dnie_like(None),
                claimed_signing_time=None,
                timestamp=None,
                archive_timestamps=(),
            ),
        ),
        b"contenido",
        NOW,
    )
    report = report_data(cades, file_name="acta.p7m", file_sha256="ab" * 32, store=store)
    assert report["signed_file"] is None
    [signature] = report["signatures"]
    assert (signature["format"], signature["packaging"]) == ("CAdES", "p7m")
    assert "scope" not in signature
    # a failed digest says nothing reassuring about the content
    assert "no se ha modificado" not in signature["explanation"]["es_PE"]


def test_a_signature_over_a_part_never_says_the_document_is_unchanged() -> None:
    """Review of the increment 6 (AM-06): the rest of the document may have changed."""
    report = report_data(
        XadesVerification((_xades_report(SignedScope.PART),), NOW),
        file_name="acta.xml",
        file_sha256="ab" * 32,
        store=TrustStore([]),
    )
    explanation = report["signatures"][0]["explanation"]["es_PE"]
    assert "no se ha modificado" not in explanation
    assert explanation.endswith(
        "La firma cubre solo una parte del documento: el resto no está firmado."
    )
