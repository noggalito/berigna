# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Simulated DNIe v2 cards whose signing certificate is issued by the test PKI."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from berigna.core.token.dnie_v2 import CertificateSlot
from sim.dnie_v2 import DnieV2Simulator
from support.pki import Pki


def make_card(pki: Pki, cn: str) -> tuple[DnieV2Simulator, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf(cn, key=key)
    der = leaf.public_bytes(serialization.Encoding.DER)
    return DnieV2Simulator(files={CertificateSlot.SIGNATURE.value: der}, private_key=key), leaf
