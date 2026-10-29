# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""APDU transport to a smart card, and its PC/SC implementation.

This is the only module that knows about pyscard: every pyscard exception is translated into
the :mod:`berigna.core.errors` hierarchy, so upper layers only ever see ERR-1xx codes.
"""

import contextlib
from collections.abc import Callable
from typing import Any, Protocol

from berigna.core.errors import (
    CardCommunicationError,
    CardInUseError,
    CardNotFoundError,
    CardRemovedError,
    CardTransientError,
    PcscUnavailableError,
)

_SCARD_E_NOT_TRANSACTED = 0x80100016
_SCARD_E_SHARING_VIOLATION = 0x8010000B
_SCARD_E_NO_SMARTCARD = 0x8010000C
_SCARD_W_REMOVED_CARD = 0x80100069
_SCARD_E_READER_UNAVAILABLE = 0x80100017
_CARD_GONE = frozenset({_SCARD_E_NO_SMARTCARD, _SCARD_W_REMOVED_CARD, _SCARD_E_READER_UNAVAILABLE})


def _hresult(exc: BaseException) -> int:
    value = getattr(exc, "hresult", -1)
    return value & 0xFFFFFFFF if isinstance(value, int) else -1


class Transport(Protocol):
    """Sends APDUs to one card and returns ``(response data, status word)``."""

    @property
    def atr(self) -> bytes: ...

    def transmit(self, apdu: bytes | bytearray) -> tuple[bytes, int]: ...

    def close(self) -> None: ...


class PcscTransport:
    """PC/SC connection held in exclusive mode and closed by powering the card off.

    Exclusive mode keeps other processes away from an authenticated session (AM-01), and
    powering the card off is the only reliable way to drop a verified PIN on the DNIe v2:
    re-selecting the applet does not (SPK-01 §8.6, ADR-0012).
    """

    def __init__(self, connection: Any, reader_name: str) -> None:
        self._connection: Any = connection
        self.reader_name = reader_name

    @classmethod
    def open_first(cls, accepts: Callable[[bytes], bool]) -> "PcscTransport":
        """Connect to the first reader whose card ATR is accepted by ``accepts``.

        Raises :class:`CardInUseError` if a reader could not be opened because another
        program holds its card, :class:`CardNotFoundError` if no supported card is present,
        and :class:`PcscUnavailableError` if the PC/SC service cannot be reached.
        """
        from smartcard.Exceptions import SmartcardException
        from smartcard.scard import SCARD_SHARE_EXCLUSIVE, SCARD_UNPOWER_CARD
        from smartcard.System import readers

        try:
            available = readers()
        except SmartcardException as exc:
            raise PcscUnavailableError(f"PC/SC service unavailable: {exc}") from exc

        in_use = False
        for reader in available:
            connection = reader.createConnection()
            try:
                connection.connect(mode=SCARD_SHARE_EXCLUSIVE, disposition=SCARD_UNPOWER_CARD)
            except SmartcardException as exc:
                in_use = in_use or _hresult(exc) == _SCARD_E_SHARING_VIOLATION
                continue
            try:
                accepted = accepts(bytes(connection.getATR()))
            except SmartcardException:
                accepted = False
            if accepted:
                return cls(connection, str(reader))
            cls._disconnect_quietly(connection)
        if in_use:
            raise CardInUseError("a card is held by another program")
        raise CardNotFoundError("no reader holds a supported card")

    @property
    def atr(self) -> bytes:
        from smartcard.Exceptions import SmartcardException

        if self._connection is None:
            raise CardCommunicationError("transport is closed")
        try:
            return bytes(self._connection.getATR())
        except SmartcardException as exc:
            self.close()
            raise CardRemovedError(f"cannot read the ATR: {exc}") from exc

    def transmit(self, apdu: bytes | bytearray) -> tuple[bytes, int]:
        from smartcard.Exceptions import NoCardException, SmartcardException

        if self._connection is None:
            raise CardCommunicationError("transport is closed")
        try:
            data, sw1, sw2 = self._connection.transmit(list(apdu))
        except SmartcardException as exc:
            if _hresult(exc) == _SCARD_E_NOT_TRANSACTED:
                raise CardTransientError("PC/SC transaction failed transiently") from exc
            gone = isinstance(exc, NoCardException) or _hresult(exc) in _CARD_GONE
            self.close()
            if gone:
                raise CardRemovedError("card removed during the operation") from exc
            raise CardCommunicationError(f"PC/SC transmit failed: {exc}") from exc
        return bytes(data), (sw1 << 8) | sw2

    def close(self) -> None:
        """Disconnect with SCARD_UNPOWER_CARD (set at connect time). Idempotent.

        Never raises: if the card or reader is already gone, there is no session left.
        """
        connection, self._connection = self._connection, None
        if connection is not None:
            self._disconnect_quietly(connection)

    @staticmethod
    def _disconnect_quietly(connection: Any) -> None:
        from smartcard.Exceptions import SmartcardException

        with contextlib.suppress(SmartcardException):
            connection.disconnect()
