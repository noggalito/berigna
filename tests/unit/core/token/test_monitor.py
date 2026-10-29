# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Device monitor (RF-001, RF-002): state derivation, change notification, PC/SC source."""

import threading
from typing import Any

import pytest

from berigna.core.errors import PcscUnavailableError
from berigna.core.token.dnie_v2 import DNIE_V2_ATR
from berigna.core.token.monitor import (
    DeviceMonitor,
    DeviceState,
    DeviceStatus,
    PcscStatusSource,
    ReaderState,
    derive_status,
)

OTHER_ATR = bytes.fromhex("3B8F8001804F0CA000000306030001000000006A")


class ScriptedSource:
    """Returns the queued reader lists one by one (repeating the last); may raise."""

    def __init__(self, *samples: tuple[ReaderState, ...] | Exception) -> None:
        self.samples = list(samples)
        self.closed = 0

    def readers(self) -> tuple[ReaderState, ...]:
        sample = self.samples.pop(0) if len(self.samples) > 1 else self.samples[0]
        if isinstance(sample, Exception):
            raise sample
        return sample

    def close(self) -> None:
        self.closed += 1


@pytest.mark.parametrize(
    ("readers", "state", "reader"),
    [
        ((), DeviceState.NO_READER, None),
        ((ReaderState("L1", None),), DeviceState.NO_CARD, None),
        ((ReaderState("L1", OTHER_ATR),), DeviceState.UNSUPPORTED_CARD, "L1"),
        ((ReaderState("L1", DNIE_V2_ATR),), DeviceState.DNIE_READY, "L1"),
        (
            (ReaderState("L1", OTHER_ATR), ReaderState("L2", DNIE_V2_ATR)),
            DeviceState.DNIE_READY,
            "L2",
        ),
    ],
    ids=["sin-lector", "sin-tarjeta", "no-compatible", "dnie", "dnie-en-segundo-lector"],
)
def test_derive_status(
    readers: tuple[ReaderState, ...], state: DeviceState, reader: str | None
) -> None:
    status = derive_status(readers)
    assert status.state is state
    assert status.reader == reader
    assert status.readers == tuple(r.name for r in readers)


def test_unsupported_card_reports_its_atr() -> None:
    """RF-002 (2): the UI shows the ATR for support."""
    assert derive_status((ReaderState("L1", OTHER_ATR),)).atr == OTHER_ATR


def test_notifies_only_changes() -> None:
    empty, card = (ReaderState("L1", None),), (ReaderState("L1", DNIE_V2_ATR),)
    seen: list[DeviceStatus] = []
    monitor = DeviceMonitor(ScriptedSource((), empty, empty, card, card, empty), seen.append)
    for _ in range(6):
        monitor.poll()
    assert [s.state for s in seen] == [
        DeviceState.NO_READER,
        DeviceState.NO_CARD,
        DeviceState.DNIE_READY,
        DeviceState.NO_CARD,
    ]
    assert monitor.status is not None
    assert monitor.status.state is DeviceState.NO_CARD


def test_pcsc_outage_and_recovery() -> None:
    """RF-001 (3): pcscd unavailable is a state of its own, and recovery is noticed."""
    card = (ReaderState("L1", DNIE_V2_ATR),)
    seen: list[DeviceStatus] = []
    monitor = DeviceMonitor(ScriptedSource(PcscUnavailableError("down"), card), seen.append)
    monitor.poll()
    monitor.poll()
    assert [s.state for s in seen] == [DeviceState.PCSC_UNAVAILABLE, DeviceState.DNIE_READY]


def test_background_thread_notifies_and_stops() -> None:
    reached = threading.Event()
    seen: list[DeviceStatus] = []

    def on_change(status: DeviceStatus) -> None:
        seen.append(status)
        if status.state is DeviceState.DNIE_READY:
            reached.set()

    source = ScriptedSource((), (ReaderState("L1", DNIE_V2_ATR),))
    monitor = DeviceMonitor(source, on_change, interval=0.01)
    monitor.start()
    with pytest.raises(RuntimeError):
        monitor.start()
    assert reached.wait(timeout=2.0)
    monitor.stop()
    assert source.closed == 1
    assert [s.state for s in seen] == [DeviceState.NO_READER, DeviceState.DNIE_READY]


# -- PcscStatusSource with a fake pyscard.scard module -----------------------------------------


class FakeScard:
    SCARD_SCOPE_USER = 0
    SCARD_S_SUCCESS = 0
    SCARD_STATE_UNAWARE = 0
    SCARD_STATE_PRESENT = 0x20
    SCARD_E_TIMEOUT = 0x8010000A
    SCARD_E_NO_READERS_AVAILABLE = 0x8010002E

    def __init__(self) -> None:
        self.establish_result = 0
        self.list_result: tuple[int, list[str]] = (0, ["L1", "L2"])
        self.status_result: tuple[int, list[tuple[str, int, list[int]]]] = (
            0,
            [("L1", 0x22, list(DNIE_V2_ATR)), ("L2", 0x12, [])],
        )
        self.contexts_released: list[Any] = []

    def SCardEstablishContext(self, scope: int) -> tuple[int, str]:  # pyscard API name
        return self.establish_result, "ctx"

    def SCardListReaders(self, context: str, groups: list[str]) -> tuple[int, list[str]]:
        return self.list_result

    def SCardGetStatusChange(
        self, context: str, timeout: int, states: list[tuple[str, int]]
    ) -> tuple[int, Any]:
        return self.status_result

    def SCardReleaseContext(self, context: str) -> int:
        self.contexts_released.append(context)
        return 0


@pytest.fixture
def fake_scard(monkeypatch: pytest.MonkeyPatch) -> FakeScard:
    fake = FakeScard()
    monkeypatch.setattr(PcscStatusSource, "_scard", lambda self: fake)
    return fake


def test_pcsc_source_reports_cards_without_connecting(fake_scard: FakeScard) -> None:
    source = PcscStatusSource()
    assert source.readers() == (ReaderState("L1", DNIE_V2_ATR), ReaderState("L2", None))
    source.close()
    source.close()
    assert fake_scard.contexts_released == ["ctx"]


def test_pcsc_source_decodes_reader_names_given_as_bytes(fake_scard: FakeScard) -> None:
    fake_scard.status_result = (0, [(b"L1", 0x12, [])])
    assert PcscStatusSource().readers() == (ReaderState("L1", None),)


def test_pcsc_source_without_readers(fake_scard: FakeScard) -> None:
    fake_scard.list_result = (FakeScard.SCARD_E_NO_READERS_AVAILABLE, [])
    assert PcscStatusSource().readers() == ()
    fake_scard.list_result = (0, [])
    assert PcscStatusSource().readers() == ()


def test_pcsc_source_errors(fake_scard: FakeScard) -> None:
    fake_scard.establish_result = 0x8010001D
    with pytest.raises(PcscUnavailableError, match="unavailable"):
        PcscStatusSource().readers()
    fake_scard.establish_result = 0
    fake_scard.list_result = (0x8010001E, [])
    source = PcscStatusSource()
    with pytest.raises(PcscUnavailableError, match="list readers"):
        source.readers()
    assert fake_scard.contexts_released == ["ctx"]  # stale context dropped
    fake_scard.list_result = (0, ["L1"])
    fake_scard.status_result = (0x80100003, [])
    with pytest.raises(PcscUnavailableError, match="reader states"):
        source.readers()


def test_pcsc_source_reuses_its_context(fake_scard: FakeScard) -> None:
    calls: list[int] = []
    original = fake_scard.SCardEstablishContext

    def counting(scope: int) -> tuple[int, str]:
        calls.append(scope)
        return original(scope)

    fake_scard.SCardEstablishContext = counting  # type: ignore[method-assign]
    source = PcscStatusSource()
    source.readers()
    source.readers()
    assert len(calls) == 1


def test_stop_without_start_releases_the_source() -> None:
    source = ScriptedSource(())
    DeviceMonitor(source, lambda status: None).stop()
    assert source.closed == 1


def test_real_scard_module_is_used_by_default() -> None:
    scard = PcscStatusSource()._scard()
    assert hasattr(scard, "SCardGetStatusChange")
