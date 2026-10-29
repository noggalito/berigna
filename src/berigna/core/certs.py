# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Conversions between the two certificate types the core uses.

berigna's own code works with ``cryptography`` certificates; pyHanko and pyhanko-certvalidator
take ``asn1crypto`` ones. Both conversions go through DER, so nothing is reinterpreted.
"""

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def to_asn1(certificate: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))


def to_cryptography(certificate: asn1_x509.Certificate) -> x509.Certificate:
    return x509.load_der_x509_certificate(certificate.dump())
