# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Shared fixtures: a test key and certificates shaped like the DNIe v2 ones."""

import datetime as dt
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from berigna.core.token.dnie_v2 import CertificateSlot
from sim.dnie_v2 import DnieV2Simulator

# Compiled catalogues of the source tree (scripts/traducciones.sh compilar, run by verificar.sh).
os.environ.setdefault(
    "BERIGNA_LOCALEDIR", str(Path(__file__).resolve().parents[1] / "build" / "locale")
)


def _key_usage(**flags: bool) -> x509.KeyUsage:
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    )
    return x509.KeyUsage(**{name: flags.get(name, False) for name in names})


def _certificate(key: rsa.RSAPrivateKey, cn: str, usage: x509.KeyUsage) -> bytes:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(usage, critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture(autouse=True)
def private_state(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The technical log of a test that starts berigna goes to a temporary folder, never to
    the user's ~/.local/state (it did, 2026-10-29)."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path_factory.mktemp("state")))


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def card_files(signing_key: rsa.RSAPrivateKey) -> dict[int, bytes]:
    return {
        CertificateSlot.SIGNATURE.value: _certificate(
            signing_key, "PRUEBA FIR 00000000 hard", _key_usage(content_commitment=True)
        ),
        CertificateSlot.AUTHENTICATION.value: _certificate(
            signing_key, "PRUEBA AUT 00000000 hard", _key_usage(digital_signature=True)
        ),
        CertificateSlot.ENCRYPTION.value: _certificate(
            signing_key,
            "PRUEBA CIF 00000000 hard",
            _key_usage(key_encipherment=True, data_encipherment=True),
        ),
    }


@pytest.fixture
def card(card_files: dict[int, bytes], signing_key: rsa.RSAPrivateKey) -> DnieV2Simulator:
    return DnieV2Simulator(files=dict(card_files), private_key=signing_key)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("BERIGNA_HIL") == "1":
        return
    skip = pytest.mark.skip(reason="prueba HIL: requiere BERIGNA_HIL=1, lector y DNIe reales")
    for item in items:
        if "hil" in item.keywords:
            item.add_marker(skip)
