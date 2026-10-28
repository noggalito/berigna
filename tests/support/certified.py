# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Certified PDFs (DocMDP, ISO 32000 §12.8.2.2) for the tests, signed in software."""

import io

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import MDPPerm
from pyhanko_certvalidator.registry import SimpleCertificateStore

from support.pki import Pki, minimal_pdf


def certified_pdf(pki: Pki, permission: MDPPerm) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf("CERTIFICADOR", key=key)
    signer = signers.SimpleSigner(
        signing_cert=asn1_x509.Certificate.load(leaf.public_bytes(serialization.Encoding.DER)),
        signing_key=asn1_keys.PrivateKeyInfo.load(
            key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ),
        cert_registry=SimpleCertificateStore(),
    )
    metadata = signers.PdfSignatureMetadata(
        field_name="Certificacion", certify=True, docmdp_permissions=permission
    )
    out = io.BytesIO()
    writer = IncrementalPdfFileWriter(io.BytesIO(minimal_pdf()))
    signers.PdfSigner(metadata, signer).sign_pdf(writer, output=out)
    return out.getvalue()
