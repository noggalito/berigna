# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""PcscTransport with a fake pyscard connection."""

from typing import Any

import pytest

from berigna.core.errors import CardCommunicationError
from berigna.core.token.transport import PcscTransport


class FakeConnection:
    def __init__(self) -> None:
        self.sent: list[list[int]] = []
        self.disconnects = 0

    def getATR(self) -> list[int]:  # pyscard API name
        return [0x3B, 0x00]

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        self.sent.append(apdu)
        return [0xAA, 0xBB], 0x90, 0x00

    def disconnect(self) -> None:
        self.disconnects += 1


def _transport() -> tuple[PcscTransport, FakeConnection]:
    connection = FakeConnection()
    fake: Any = connection
    return PcscTransport(fake, "Fake reader"), connection


def test_transmit_returns_data_and_status_word() -> None:
    transport, connection = _transport()
    assert transport.transmit(b"\x00\xa4\x04\x00") == (b"\xaa\xbb", 0x9000)
    assert connection.sent == [[0x00, 0xA4, 0x04, 0x00]]
    assert transport.atr == b"\x3b\x00"


def test_close_is_idempotent_and_blocks_further_use() -> None:
    transport, connection = _transport()
    transport.close()
    transport.close()
    assert connection.disconnects == 1
    with pytest.raises(CardCommunicationError):
        transport.transmit(b"\x00\xa4\x04\x00")


class FakeReader:
    def __init__(self, name: str, atr: list[int] | None) -> None:
        self.name, self.atr = name, atr
        self.connection: FakeReaderConnection | None = None

    def createConnection(self) -> "FakeReaderConnection":  # pyscard API name
        self.connection = FakeReaderConnection(self.atr)
        return self.connection

    def __str__(self) -> str:
        return self.name


class FakeReaderConnection(FakeConnection):
    def __init__(self, atr: list[int] | None) -> None:
        super().__init__()
        self._atr = atr
        self.connect_args: dict[str, Any] = {}

    def connect(self, **kwargs: Any) -> None:
        from smartcard.Exceptions import NoCardException

        if self._atr is None:
            raise NoCardException("empty reader", hresult=0)
        self.connect_args = kwargs

    def getATR(self) -> list[int]:
        return list(self._atr or [])


def test_open_first_uses_exclusive_mode_and_power_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-0012 / AM-01: exclusive session, card powered off on disconnect."""
    from smartcard.scard import SCARD_SHARE_EXCLUSIVE, SCARD_UNPOWER_CARD

    empty, other, dnie = (
        FakeReader("vacío", None),
        FakeReader("otra", [0x3B, 0x01]),
        FakeReader("dnie", [0x3B, 0x02]),
    )
    monkeypatch.setattr("smartcard.System.readers", lambda: [empty, other, dnie])
    transport = PcscTransport.open_first(lambda atr: atr == b"\x3b\x02")
    assert transport.reader_name == "dnie"
    assert other.connection is not None
    assert other.connection.disconnects == 1
    assert dnie.connection is not None
    assert dnie.connection.connect_args == {
        "mode": SCARD_SHARE_EXCLUSIVE,
        "disposition": SCARD_UNPOWER_CARD,
    }


def test_open_first_without_supported_card(monkeypatch: pytest.MonkeyPatch) -> None:
    from berigna.core.errors import CardNotFoundError

    monkeypatch.setattr("smartcard.System.readers", lambda: [FakeReader("otra", [0x3B, 0x01])])
    with pytest.raises(CardNotFoundError):
        PcscTransport.open_first(lambda atr: False)


class FailingConnection(FakeConnection):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        raise self.error

    def disconnect(self) -> None:
        super().disconnect()
        raise self.error


def test_card_removed_mid_operation_is_translated_and_session_closed() -> None:
    """O-2 / PR-SEG-04: pyscard never reaches upper layers; the session is closed."""
    from smartcard.Exceptions import NoCardException

    from berigna.core.errors import CardRemovedError

    connection = FailingConnection(NoCardException("removed", hresult=0x80100069))
    fake: Any = connection
    transport = PcscTransport(fake, "r")
    with pytest.raises(CardRemovedError):
        transport.transmit(b"\x00\xa4\x04\x00")
    assert connection.disconnects == 1
    transport.close()  # idempotent and silent even though disconnect fails
    assert connection.disconnects == 1


def test_other_transmit_failures_become_communication_errors() -> None:
    from smartcard.Exceptions import CardConnectionException

    connection = FailingConnection(CardConnectionException("io error", hresult=0x8010002F))
    fake: Any = connection
    with pytest.raises(CardCommunicationError, match="transmit failed"):
        PcscTransport(fake, "r").transmit(b"\x00\xa4\x04\x00")


def test_card_held_by_another_program(monkeypatch: pytest.MonkeyPatch) -> None:
    """O-1: a sharing violation is reported as CardInUseError, not as a missing card."""
    from smartcard.Exceptions import CardConnectionException

    from berigna.core.errors import CardInUseError

    class BusyConnection(FakeReaderConnection):
        def connect(self, **kwargs: Any) -> None:
            raise CardConnectionException("busy", hresult=0x8010000B)

    class BusyReader(FakeReader):
        def createConnection(self) -> FakeReaderConnection:
            return BusyConnection([0x3B, 0x02])

    monkeypatch.setattr("smartcard.System.readers", lambda: [BusyReader("ocupado", None)])
    with pytest.raises(CardInUseError):
        PcscTransport.open_first(lambda atr: True)


def test_pcsc_service_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    from smartcard.Exceptions import ListReadersException

    from berigna.core.errors import PcscUnavailableError

    def no_service() -> list[Any]:
        raise ListReadersException(0x8010001D)

    monkeypatch.setattr("smartcard.System.readers", no_service)
    with pytest.raises(PcscUnavailableError):
        PcscTransport.open_first(lambda atr: True)


def test_closed_transport_has_no_atr() -> None:
    transport, _ = _transport()
    transport.close()
    with pytest.raises(CardCommunicationError):
        _ = transport.atr


def test_unreadable_atr_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    from smartcard.Exceptions import CardConnectionException

    from berigna.core.errors import CardNotFoundError

    class MuteConnection(FakeReaderConnection):
        def getATR(self) -> list[int]:
            raise CardConnectionException("no ATR", hresult=0x80100016)

    class MuteReader(FakeReader):
        def createConnection(self) -> FakeReaderConnection:
            self.connection = MuteConnection([0x3B])
            return self.connection

    reader = MuteReader("mudo", [0x3B])
    monkeypatch.setattr("smartcard.System.readers", lambda: [reader])
    with pytest.raises(CardNotFoundError):
        PcscTransport.open_first(lambda atr: True)
    assert reader.connection is not None
    assert reader.connection.disconnects == 1


def test_transient_failure_keeps_the_session_open() -> None:
    from smartcard.Exceptions import CardConnectionException

    from berigna.core.errors import CardTransientError

    connection = FailingConnection(CardConnectionException("tx", hresult=0x80100016))
    fake: Any = connection
    transport = PcscTransport(fake, "r")
    with pytest.raises(CardTransientError):
        transport.transmit(b"\x00\xa4\x04\x00")
    assert connection.disconnects == 0
