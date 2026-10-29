# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""RF-006 on hardware and on the real IOFE services. NO PIN is sent.

Reads the signing certificate from a real DNIe v2 and validates it online: chain up to
ECERNEP PERU CA ROOT 3, OCSP of RENIEC for the certificate and the ARLs for the CAs.

    BERIGNA_HIL=1 pytest -m hil
"""

import time

import pytest
from cryptography import x509

from berigna.core.token.dnie_v2 import DnieV2Token, is_dnie_v2
from berigna.core.token.transport import PcscTransport
from berigna.core.trust import TrustStore
from berigna.core.validation import check_signer

pytestmark = pytest.mark.hil


def test_real_dnie_certificate_is_valid_online() -> None:
    with DnieV2Token(PcscTransport.open_first(is_dnie_v2)) as token:
        certificate = token.signing_certificate()
    start = time.perf_counter()
    result = check_signer(certificate, TrustStore.load_bundled(), online=True)
    elapsed = time.perf_counter() - start
    names = [
        c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value for c in result.chain
    ]
    assert result.revocation_checked, "OCSP/ARL de RENIEC no disponibles"
    assert names[:3] == ["ECERNEP PERU CA ROOT 3", "ECEP-RENIEC", "ECEP-RENIEC CA Class 2 II"]
    assert elapsed < 10.0, f"validación en línea: {elapsed:.1f} s"
