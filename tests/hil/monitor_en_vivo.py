# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Manual HIL check of RF-001/RF-002: prints every device change with its time. NO PIN.

Run it, then unplug and plug the reader and remove and insert the DNIe; each change must
appear in under 2 seconds. Stop with Ctrl+C.

    .venv/bin/python tests/hil/monitor_en_vivo.py
"""

import time

from berigna.core.token.monitor import DeviceMonitor, DeviceStatus, PcscStatusSource

MESSAGES = {
    "pcsc-unavailable": "Servicio PC/SC no disponible (¿pcscd?)",
    "no-reader": "Conecta un lector de tarjetas",
    "no-card": "Inserta tu DNIe en el lector",
    "unsupported-card": "Tarjeta no compatible",
    "dnie-ready": "DNIe listo",
}


def main() -> None:
    start = time.monotonic()

    def show(status: DeviceStatus) -> None:
        detail = f" · {status.reader}" if status.reader else ""
        if status.atr and status.state.value == "unsupported-card":
            detail += f" · ATR {status.atr.hex().upper()}"
        print(
            f"[{time.monotonic() - start:7.2f} s] {MESSAGES[status.state.value]}{detail}",
            flush=True,
        )

    monitor = DeviceMonitor(PcscStatusSource(), show)
    monitor.start()
    print("Monitor activo (sondeo cada 0,5 s). Conecta y desconecta el lector y el DNIe. Ctrl+C.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
