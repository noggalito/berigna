# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Hot-plug monitor of readers and cards (RF-001, RF-002).

The monitor never connects to a card: it uses ``SCardGetStatusChange``, which reports readers,
card presence and ATR even while a signing session holds the card exclusively. It polls every
``interval`` seconds (0.5 s by default, well under the 2 s of RF-001) and calls ``on_change``
from its own thread only when the derived :class:`DeviceStatus` changes; a GTK UI must hand
the call to the main loop (for example with ``GLib.idle_add``).
"""

import enum
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from berigna.core.errors import PcscUnavailableError
from berigna.core.token.dnie_v2 import is_dnie_v2


@dataclass(frozen=True)
class ReaderState:
    name: str
    atr: bytes | None  # None when the reader is empty


class StatusSource(Protocol):
    """Reports the readers and their cards; raises :class:`PcscUnavailableError`."""

    def readers(self) -> tuple[ReaderState, ...]: ...

    def close(self) -> None: ...


class DeviceState(enum.Enum):
    PCSC_UNAVAILABLE = "pcsc-unavailable"  # ERR-107: "instala/arranca pcscd"
    NO_READER = "no-reader"  # "Conecta un lector de tarjetas"
    NO_CARD = "no-card"  # "Inserta tu DNIe en el lector"
    UNSUPPORTED_CARD = "unsupported-card"  # "Tarjeta no compatible" + ATR (RF-002)
    DNIE_READY = "dnie-ready"


@dataclass(frozen=True)
class DeviceStatus:
    state: DeviceState
    readers: tuple[str, ...] = ()
    reader: str | None = None  # reader holding the relevant card
    atr: bytes | None = None


def derive_status(readers: tuple[ReaderState, ...]) -> DeviceStatus:
    """A DNIe v2 in any reader wins; otherwise report the first unsupported card, if any."""
    names = tuple(r.name for r in readers)
    for reader in readers:
        if reader.atr is not None and is_dnie_v2(reader.atr):
            return DeviceStatus(DeviceState.DNIE_READY, names, reader.name, reader.atr)
    for reader in readers:
        if reader.atr is not None:
            return DeviceStatus(DeviceState.UNSUPPORTED_CARD, names, reader.name, reader.atr)
    return DeviceStatus(DeviceState.NO_CARD if readers else DeviceState.NO_READER, names)


class PcscStatusSource:
    """:class:`StatusSource` over pcsc-lite. Re-establishes its context after pcscd restarts."""

    def __init__(self) -> None:
        self._context: Any = None

    def _scard(self) -> Any:
        from smartcard import scard

        return scard

    def _ensure_context(self) -> Any:
        scard = self._scard()
        if self._context is None:
            result, context = scard.SCardEstablishContext(scard.SCARD_SCOPE_USER)
            if result != scard.SCARD_S_SUCCESS:
                raise PcscUnavailableError(f"PC/SC service unavailable ({result & 0xFFFFFFFF:#x})")
            self._context = context
        return self._context

    def readers(self) -> tuple[ReaderState, ...]:
        scard = self._scard()
        context = self._ensure_context()
        result, names = scard.SCardListReaders(context, [])
        if result == scard.SCARD_E_NO_READERS_AVAILABLE:
            return ()
        if result != scard.SCARD_S_SUCCESS:
            self.close()  # the context may be stale (pcscd restarted); retry next poll
            raise PcscUnavailableError(f"cannot list readers ({result & 0xFFFFFFFF:#x})")
        if not names:
            return ()
        query = [(name, scard.SCARD_STATE_UNAWARE) for name in names]
        result, states = scard.SCardGetStatusChange(context, 0, query)
        if result not in (scard.SCARD_S_SUCCESS, scard.SCARD_E_TIMEOUT):
            self.close()
            raise PcscUnavailableError(f"cannot read reader states ({result & 0xFFFFFFFF:#x})")
        return tuple(
            ReaderState(
                name.decode() if isinstance(name, bytes) else name,  # str in pyscard >= 2
                bytes(atr) if event & scard.SCARD_STATE_PRESENT and atr else None,
            )
            for name, event, atr in states
        )

    def close(self) -> None:
        if self._context is not None:
            context, self._context = self._context, None
            self._scard().SCardReleaseContext(context)


class DeviceMonitor:
    """Polls a :class:`StatusSource` and notifies changes of :class:`DeviceStatus`."""

    def __init__(
        self,
        source: StatusSource,
        on_change: Callable[[DeviceStatus], None],
        interval: float = 0.5,
    ) -> None:
        self._source = source
        self._on_change = on_change
        self._interval = interval
        self._last: DeviceStatus | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def status(self) -> DeviceStatus | None:
        return self._last

    def poll(self) -> DeviceStatus:
        """Take one sample; notify and return the status (notifies only on change)."""
        try:
            status = derive_status(self._source.readers())
        except PcscUnavailableError:
            status = DeviceStatus(DeviceState.PCSC_UNAVAILABLE)
        if status != self._last:
            self._last = status
            self._on_change(status)
        return status

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("monitor already started")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="berigna-device-monitor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None
        self._source.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll()
            self._stop.wait(self._interval)
