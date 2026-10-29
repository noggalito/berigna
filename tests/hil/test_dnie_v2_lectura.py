# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Hardware-in-the-loop tests with a real reader and DNIe v2. NO PIN is ever sent here.

Run with:  BERIGNA_HIL=1 pytest -m hil
"""

import time

import pytest
from cryptography import x509

from berigna.core.errors import NotAuthenticatedError
from berigna.core.token.dnie_v2 import DnieV2Token, is_dnie_v2
from berigna.core.token.transport import PcscTransport

pytestmark = pytest.mark.hil


def test_reads_the_signing_certificate_from_a_real_dnie() -> None:
    """PR-TOK-02 / RF-003 on hardware: non-repudiation certificate in under 1 s.

    The first PC/SC call of a process loads pyscard and creates the PC/SC context (~0.25 s);
    the application pays it once at start-up, so it is excluded from the measurement.
    """
    from smartcard.System import readers

    readers()  # warm-up, outside the timed section
    start = time.perf_counter()
    with DnieV2Token(PcscTransport.open_first(is_dnie_v2)) as token:
        cert = token.signing_certificate()
    elapsed = time.perf_counter() - start
    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert issuer == "ECEP-RENIEC CA Class 2 II"
    assert elapsed < 1.0, f"lectura del certificado: {elapsed:.2f} s"


def test_a_fresh_session_is_not_authenticated() -> None:
    """PR-SEG-05 on hardware: after the previous session was closed (card powered off), a new
    one cannot sign without VERIFY. The driver refuses locally; the card would answer 6982."""
    with DnieV2Token(PcscTransport.open_first(is_dnie_v2)) as token:
        assert token.probe_alive()
        assert not token.authenticated
        with pytest.raises(NotAuthenticatedError):
            token.sign_digest(bytes(32))
