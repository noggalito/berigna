# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Stand-ins for the dialogs of the interface."""

from berigna.core.token.pin import Pin
from berigna.core.validation import SignerCheck


class PinPrompt:
    """Stands in for the UI dialog; records what it was shown."""

    def __init__(self, answer: str | None = "123456") -> None:
        self.answer = answer
        self.shown: list[SignerCheck] = []
        self.pins: list[Pin] = []

    def __call__(self, check: SignerCheck) -> Pin | None:
        self.shown.append(check)
        if self.answer is None:
            return None
        pin = Pin(self.answer)
        self.pins.append(pin)
        return pin
