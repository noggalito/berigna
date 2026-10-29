# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Pin container: P-02 to P-04 (never shown, never serialised, wipeable)."""

import pickle

import pytest

from berigna.core.token.pin import Pin


def test_value_is_never_shown() -> None:
    pin = Pin("123456")
    assert repr(pin) == "Pin(***)"
    assert str(pin) == "Pin(***)"
    assert f"{pin}" == "Pin(***)"
    assert "123456" not in repr(pin)


def test_cannot_be_compared_hashed_or_pickled() -> None:
    pin = Pin("123456")
    with pytest.raises(TypeError):
        _ = pin == Pin("123456")
    with pytest.raises(TypeError):
        hash(pin)
    with pytest.raises(TypeError):
        pickle.dumps(pin)


def test_wipe_zeroes_the_buffer() -> None:
    pin = Pin("123456")
    buffer = pin.buffer()
    pin.wipe()
    assert pin.wiped
    assert buffer == bytearray(6)


def test_bytearray_source_is_wiped_on_construction() -> None:
    source = bytearray(b"123456")
    pin = Pin(source)
    assert source == bytearray(6)
    assert len(pin) == 6


@pytest.mark.parametrize("value", ["", b"", "x" * 256])
def test_rejects_empty_or_oversized(value: str | bytes) -> None:
    with pytest.raises(ValueError, match="PIN"):
        Pin(value)


def test_rejects_non_ascii() -> None:
    with pytest.raises(UnicodeEncodeError):
        Pin("12345ñ")
