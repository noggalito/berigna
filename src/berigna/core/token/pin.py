# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""PIN container that never shows its value and can be wiped (rules P-02 to P-04)."""

from typing import NoReturn

_MAX_PIN_LENGTH = 255  # An APDU body cannot carry more; the card enforces its own limits.


class Pin:
    """A PIN held in a mutable buffer.

    The value is never part of ``repr``/``str``, cannot be pickled or compared, and is
    overwritten with zeros by :meth:`wipe`. Python may still keep copies elsewhere (for
    example inside the GTK entry or the PC/SC binding); that limitation is documented in P-04.
    """

    __slots__ = ("_buffer",)

    def __init__(self, value: str | bytes | bytearray) -> None:
        raw = value.encode("ascii") if isinstance(value, str) else value
        if not raw:
            raise ValueError("empty PIN")
        if len(raw) > _MAX_PIN_LENGTH:
            raise ValueError("PIN too long")
        self._buffer = bytearray(raw)
        if isinstance(value, bytearray):
            for i in range(len(value)):
                value[i] = 0

    def __len__(self) -> int:
        return len(self._buffer)

    def __repr__(self) -> str:
        return "Pin(***)"

    __str__ = __repr__

    def __eq__(self, other: object) -> NoReturn:
        raise TypeError("PINs cannot be compared")

    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self) -> NoReturn:
        raise TypeError("PINs cannot be serialised")

    @property
    def wiped(self) -> bool:
        return not any(self._buffer)

    def buffer(self) -> bytearray:
        """Return the live buffer. Callers must not keep references to it."""
        return self._buffer

    def wipe(self) -> None:
        for i in range(len(self._buffer)):
            self._buffer[i] = 0
