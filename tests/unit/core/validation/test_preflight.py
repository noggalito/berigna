# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signer check before the PIN (RF-006): PR-VAL-02 to PR-VAL-05, PR-TOK-04."""

import datetime as dt

import pytest
import requests

from berigna.core.errors import (
    CertificateExpiredError,
    CertificateRevokedError,
    CertificateValidationError,
    UntrustedCertificateError,
)
from berigna.core.trust import TrustedCertificate, TrustStore
from berigna.core.validation import RevocationNote, check_signer
from support.pki import Pki, build_pki


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def test_valid_certificate_with_fresh_ocsp(pki: Pki) -> None:
    leaf = pki.leaf("FIRMANTE VALIDO")
    result = check_signer(
        leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
    )
    assert result.revocation_checked
    assert not result.only_basic_level
    assert result.revocation_note is None
    assert [c.subject for c in result.chain] == [pki.root.subject, pki.ca.subject, leaf.subject]


def test_revoked_certificate_is_rejected(pki: Pki) -> None:
    leaf = pki.leaf("FIRMANTE REVOCADO")
    with pytest.raises(CertificateRevokedError):
        check_signer(
            leaf,
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf, revoked=True)],
            crls=[pki.arl()],
        )


def test_revoked_intermediate_is_rejected(pki: Pki) -> None:
    leaf = pki.leaf("FIRMANTE CON CA REVOCADA")
    with pytest.raises(CertificateRevokedError):
        check_signer(
            leaf,
            pki.store,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],
            crls=[pki.arl(revoke_ca=True)],
        )


@pytest.mark.parametrize("days", [(-400, -10), (5, 400)], ids=["caducado", "aun-no-valido"])
def test_certificate_outside_its_validity_is_rejected(pki: Pki, days: tuple[int, int]) -> None:
    leaf = pki.leaf("FIRMANTE FUERA DE VIGENCIA", days=days)
    with pytest.raises(CertificateExpiredError):
        check_signer(
            leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
        )


def test_certificate_outside_the_iofe_is_rejected(pki: Pki) -> None:
    other_root_only = TrustStore([TrustedCertificate(pki.ca, "intermediate", "TEST")])
    leaf = pki.leaf("FIRMANTE SIN RAIZ")
    with pytest.raises(UntrustedCertificateError):
        check_signer(
            leaf, other_root_only, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
        )


def test_certificate_without_non_repudiation_is_rejected(pki: Pki) -> None:
    leaf = pki.leaf("CERTIFICADO DE AUTENTICACION", non_repudiation=False)
    with pytest.raises(CertificateValidationError):
        check_signer(
            leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
        )


def test_without_revocation_data_only_basic_level_is_allowed(pki: Pki) -> None:
    """RF-006 (2): no network -> not a rejection, but B-B only with a warning."""
    leaf = pki.leaf("FIRMANTE SIN RED")
    result = check_signer(leaf, pki.store, online=False)
    assert not result.revocation_checked
    assert result.only_basic_level
    assert result.revocation_note is RevocationNote.OFFLINE
    assert result.chain[-1] == leaf


def test_unreachable_responders_degrade_to_basic_level(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Online, but OCSP and CRL cannot be fetched: B-B only, and the note says why."""
    urls: list[str] = []

    def refuse(url: str, *args: object, **kwargs: object) -> requests.Response:
        urls.append(url)
        raise requests.ConnectionError(f"no route to {url}")

    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(requests, "post", refuse)
    leaf = pki.leaf("FIRMANTE CON OCSP CAIDO")
    result = check_signer(leaf, pki.store, online=True, timeout=1.0)
    assert result.only_basic_level
    assert result.revocation_note is RevocationNote.UNAVAILABLE
    assert urls  # the responders were actually tried


def test_expired_certificate_is_rejected_even_without_revocation_data(pki: Pki) -> None:
    leaf = pki.leaf("CADUCADO SIN RED", days=(-400, -10))
    with pytest.raises(CertificateExpiredError):
        check_signer(leaf, pki.store, online=False)


def test_ocsp_answer_dated_after_the_moment_was_fixed(pki: Pki) -> None:
    """RENIEC can take seconds to answer (R-17): its response is dated after "now" was fixed,
    which pyhanko-certvalidator's default tolerance of 1 s rejected as "too recent"."""
    leaf = pki.leaf("FIRMANTE RESPUESTA LENTA")
    # pki.ocsp dates thisUpdate 5 minutes before ``at``: here, 2 minutes after now.
    later = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=7)
    result = check_signer(
        leaf, pki.store, online=False, ocsp_responses=[pki.ocsp(leaf, at=later)], crls=[pki.arl()]
    )
    assert result.revocation_checked
