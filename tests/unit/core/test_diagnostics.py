# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Diagnosis of the reader, the DNIe and the services (CU-07, RF-007)."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from berigna.core.diagnostics import Result, Status, Step, diagnose
from berigna.core.errors import CardRemovedError
from berigna.core.token.dnie_v2 import CertificateSlot, DnieV2Token
from berigna.core.token.monitor import DeviceState, DeviceStatus
from sim.dnie_v2 import DnieV2Simulator
from support.pki import NOW, Pki, build_pki
from support.tsa import make_timestamper

READY = DeviceStatus(DeviceState.DNIE_READY, ("innovatech 00",), "innovatech 00", b"\x3b\x8f")


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


def _token(pki: Pki, days: tuple[int, int] = (-1, 365)) -> tuple[DnieV2Simulator, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf("QUISPE MAMANI ROSA FIR 87654321 hard", key=key, days=days)
    der = leaf.public_bytes(serialization.Encoding.DER)
    card = DnieV2Simulator(files={CertificateSlot.SIGNATURE.value: der}, private_key=key)
    return card, pki.ocsp(leaf)


def _statuses(results: list[Result]) -> dict[Step, Status]:
    return {result.step: result.status for result in results}


def test_everything_in_order(pki: Pki) -> None:
    card, ocsp = _token(pki)
    results = diagnose(
        READY,
        open_token=lambda: DnieV2Token(card),
        store=pki.store,
        timestamper=None,
        online=False,
        moment=NOW,
        ocsp_responses=[ocsp],
        crls=[pki.arl()],
    )
    assert [r.step for r in results] == list(Step)
    statuses = _statuses(results)
    assert {statuses[step] for step in list(Step)[:5]} == {Status.OK}
    certificate = results[3].facts
    assert certificate["signer"] == "QUISPE MAMANI ROSA FIR ****4321 hard"
    assert certificate["days"] == "365"
    assert "87654321" not in str(results)  # never the full DNI


def test_tsa_that_answers(pki: Pki) -> None:
    stamper, _tsa = make_timestamper(pki)
    results = diagnose(
        DeviceStatus(DeviceState.NO_READER),
        open_token=DnieV2Token,
        store=pki.store,
        timestamper=stamper,
    )
    assert results[5].status is Status.OK


def test_certificate_about_to_expire_and_revocation_not_checked(pki: Pki) -> None:
    card, _ocsp = _token(pki, days=(-1, 12))
    results = diagnose(
        READY,
        open_token=lambda: DnieV2Token(card),
        store=pki.store,
        timestamper=None,
        online=False,
        moment=NOW,
    )
    statuses = _statuses(results)
    assert statuses[Step.CERTIFICATE] is Status.WARNING
    assert results[3].facts["days"] == "12"
    assert statuses[Step.VALIDATION] is Status.WARNING  # offline: B-B only
    assert results[4].facts["note"] == "offline"
    assert statuses[Step.TSA] is Status.SKIPPED
    assert results[5].facts["configured"] == "False"


def test_expired_certificate(pki: Pki) -> None:
    card, ocsp = _token(pki, days=(-400, -2))
    results = diagnose(
        READY,
        open_token=lambda: DnieV2Token(card),
        store=pki.store,
        timestamper=None,
        moment=NOW,
        ocsp_responses=[ocsp],
    )
    assert results[3].status is Status.ERROR
    assert results[3].code == "ERR-211"
    assert results[4].status is Status.ERROR
    assert results[4].code == "ERR-211"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (None, [Status.ERROR, Status.SKIPPED, Status.SKIPPED]),
        (
            DeviceStatus(DeviceState.PCSC_UNAVAILABLE),
            [Status.ERROR, Status.SKIPPED, Status.SKIPPED],
        ),
        (DeviceStatus(DeviceState.NO_READER), [Status.OK, Status.ERROR, Status.SKIPPED]),
        (DeviceStatus(DeviceState.NO_CARD, ("lector",)), [Status.OK, Status.OK, Status.ERROR]),
        (
            DeviceStatus(DeviceState.UNSUPPORTED_CARD, ("lector",), "lector", b"\x3b\x00"),
            [Status.OK, Status.OK, Status.ERROR],
        ),
    ],
)
def test_earlier_failures_skip_the_card_steps(
    pki: Pki, status: DeviceStatus | None, expected: list[Status]
) -> None:
    def no_token() -> DnieV2Token:
        raise AssertionError("the card is not opened when an earlier step failed")

    results = diagnose(status, open_token=no_token, store=pki.store, timestamper=None)
    assert [r.status for r in results[:3]] == expected
    assert results[3].status is Status.SKIPPED
    assert results[4].status is Status.SKIPPED
    if status is not None and status.atr:
        assert results[2].facts == {"atr": "3B 00"}


def test_card_that_cannot_be_read(pki: Pki) -> None:
    def removed() -> DnieV2Token:
        raise CardRemovedError("removed")

    results = diagnose(READY, open_token=removed, store=pki.store, timestamper=None)
    assert (results[3].status, results[3].code) == (Status.ERROR, "ERR-105")
    assert results[4].status is Status.SKIPPED


def test_tsa_that_does_not_answer(pki: Pki) -> None:
    from pyhanko.sign.timestamps import HTTPTimeStamper

    card, ocsp = _token(pki)
    results = diagnose(
        READY,
        open_token=lambda: DnieV2Token(card),
        store=pki.store,
        timestamper=HTTPTimeStamper("http://127.0.0.1:9/tsa", timeout=1),
        moment=NOW,
        ocsp_responses=[ocsp],
    )
    assert (results[5].status, results[5].code) == (Status.ERROR, "ERR-305")


def test_validates_now_with_its_tolerance(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without a moment the certificate is validated "now" (moment None), which gives RENIEC's
    OCSP answers the clock tolerance of CURRENT_TIME_TOLERANCE; a fixed moment made a real
    answer look too recent and the revocation "unavailable" (2026-10-29)."""
    import berigna.core.diagnostics as diagnostics

    card, _ocsp = _token(pki)
    seen: list[object] = []
    real = diagnostics.check_signer

    def spy(*args: object, **kwargs: object) -> object:
        seen.append(kwargs["moment"])
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(diagnostics, "check_signer", spy)
    diagnose(
        READY, open_token=lambda: DnieV2Token(card), store=pki.store, timestamper=None, online=False
    )
    assert seen == [None]
