# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Trust store: bundled IOFE anchors, integrity against the manifest (AM-08), user anchors."""

import datetime as dt
import json
import shutil
from importlib import resources
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from berigna.core.errors import InvalidAnchorError, TrustStoreIntegrityError
from berigna.core.trust import TrustStore

ROOT_3 = "96508217c36f3bbc556e2e07d7ab50c40da8027c388235813322e41b87a568be"
CLASS_2_II = "ec94327a45c45a928104d389b352576918b8c072327204e15e1f88547d860a42"


@pytest.fixture
def anchors(tmp_path: Path) -> Path:
    with resources.as_file(resources.files("berigna.core.trust") / "anchors") as source:
        shutil.copytree(source, tmp_path / "anchors")
    return tmp_path / "anchors"


def _common_names(certificates: list[x509.Certificate]) -> set[str]:
    return {
        str(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value) for c in certificates
    }


def _make_cert(tmp_path: Path, name: str, *, ca: bool) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / f"{name}.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return path


def test_bundled_store_contains_both_iofe_hierarchies() -> None:
    store = TrustStore.load_bundled()
    assert _common_names(store.roots) == {"ECERNEP PERU CA ROOT 3", "ECERNEP PERU CA ROOT 5"}
    assert _common_names(store.intermediates) == {
        "ECEP-RENIEC",
        "ECEP-RENIEC CA Class 2 II",
        "ECEP-RENIEC CA ROOT 5",
        "ECEP-RENIEC CA Class 3",
    }
    fingerprints = {entry.sha256 for entry in store.entries}
    assert {ROOT_3, CLASS_2_II} <= fingerprints  # same values as SPK-02 §3.1
    assert not any(entry.user_added for entry in store.entries)


def test_tampered_certificate_invalidates_the_store(anchors: Path, tmp_path: Path) -> None:
    other = _make_cert(tmp_path, "intruso", ca=True)
    shutil.copy(other, anchors / "ecernep-peru-ca-root-3.pem")
    with pytest.raises(TrustStoreIntegrityError, match="SHA-256"):
        TrustStore.load_directory(anchors)


def test_tampered_manifest_invalidates_the_store(anchors: Path) -> None:
    manifest = json.loads((anchors / "manifest.json").read_text())
    manifest["certificates"][0]["sha256"] = "00" * 32
    (anchors / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(TrustStoreIntegrityError):
        TrustStore.load_directory(anchors)


def test_unlisted_or_missing_files_invalidate_the_store(anchors: Path, tmp_path: Path) -> None:
    shutil.copy(_make_cert(tmp_path, "extra", ca=True), anchors / "extra.pem")
    with pytest.raises(TrustStoreIntegrityError, match="disagree"):
        TrustStore.load_directory(anchors)
    (anchors / "extra.pem").unlink()
    (anchors / "ecep-reniec.pem").unlink()
    with pytest.raises(TrustStoreIntegrityError, match="disagree"):
        TrustStore.load_directory(anchors)


def test_role_must_match_the_certificate(anchors: Path) -> None:
    manifest = json.loads((anchors / "manifest.json").read_text())
    for item in manifest["certificates"]:
        if item["file"] == "ecep-reniec.pem":
            item["role"] = "root"  # an intermediate disguised as a root
    (anchors / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(TrustStoreIntegrityError, match="role"):
        TrustStore.load_directory(anchors)


def test_unreadable_manifest(anchors: Path) -> None:
    (anchors / "manifest.json").write_text("{not json")
    with pytest.raises(TrustStoreIntegrityError, match="manifest"):
        TrustStore.load_directory(anchors)


def test_user_anchors_are_flagged(tmp_path: Path) -> None:
    user_dir = tmp_path / "usuario"
    user_dir.mkdir()
    anchor = _make_cert(user_dir, "CA PROPIA", ca=True)
    store = TrustStore.load_bundled().with_user_anchors(user_dir)
    certificate = x509.load_pem_x509_certificate(anchor.read_bytes())
    assert store.is_user_anchor(certificate)
    assert "CA PROPIA" in _common_names(store.roots)
    assert not store.is_user_anchor(store.entries[0].certificate)


def test_user_anchor_must_be_a_ca(tmp_path: Path) -> None:
    user_dir = tmp_path / "usuario"
    user_dir.mkdir()
    _make_cert(user_dir, "NO ES CA", ca=False)
    with pytest.raises(InvalidAnchorError):
        TrustStore.load_bundled().with_user_anchors(user_dir)


def test_missing_user_directory_is_ignored(tmp_path: Path) -> None:
    store = TrustStore.load_bundled()
    assert len(store.with_user_anchors(tmp_path / "no-existe").entries) == len(store.entries)


def test_unknown_role_invalidates_the_store(anchors: Path) -> None:
    manifest = json.loads((anchors / "manifest.json").read_text())
    manifest["certificates"][0]["role"] = "otro"
    (anchors / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(TrustStoreIntegrityError, match="valid role"):
        TrustStore.load_directory(anchors)


def test_certificate_without_basic_constraints_is_not_a_ca(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SIN BC")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    user_dir = tmp_path / "usuario"
    user_dir.mkdir()
    (user_dir / "sin-bc.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(InvalidAnchorError):
        TrustStore.load_bundled().with_user_anchors(user_dir)
