# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Device monitor on real hardware (RF-001, RF-002). NO PIN is sent.

BERIGNA_HIL=1 pytest -m hil
"""

import pytest

from berigna.core.token.dnie_v2 import DnieV2Token, is_dnie_v2
from berigna.core.token.monitor import DeviceMonitor, DeviceState, DeviceStatus, PcscStatusSource
from berigna.core.token.transport import PcscTransport

pytestmark = pytest.mark.hil


def test_monitor_sees_the_dnie() -> None:
    seen: list[DeviceStatus] = []
    monitor = DeviceMonitor(PcscStatusSource(), seen.append)
    try:
        status = monitor.poll()
    finally:
        monitor.stop()
    assert status.state is DeviceState.DNIE_READY
    assert status.reader in status.readers
    assert seen == [status]


def test_monitor_does_not_disturb_an_exclusive_session() -> None:
    """The monitor keeps working while a session holds the card, and the session keeps
    working while the monitor polls: the monitor never connects to the card."""
    monitor = DeviceMonitor(PcscStatusSource(), lambda status: None)
    try:
        with DnieV2Token(PcscTransport.open_first(is_dnie_v2)) as token:
            for _ in range(5):
                assert monitor.poll().state is DeviceState.DNIE_READY
                assert token.probe_alive()
            token.read_certificate()
    finally:
        monitor.stop()
