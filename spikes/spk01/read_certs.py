# SPDX-License-Identifier: GPL-3.0-or-later
# Prototipo de investigación (spike). No es código de producción.
"""SPK-01: read the public certificates from a Peruvian DNIe v2.

Read-only: SELECT application, SELECT file, READ BINARY (odd INS).
Never sends VERIFY (PIN) or any security-environment / signing command.
"""
import sys
from pathlib import Path

from smartcard.System import readers

PKI_AID = bytes.fromhex("E828BD080FD250") + b"Generic"
CERT_FILES = {"firma": 0x001D, "autenticacion": 0x001C, "cifrado": 0x001B}
CHUNK = 0xE4
ALLOWED_INS = {0xA4, 0xB1}  # SELECT, READ BINARY (odd)

out_dir = Path(sys.argv[1])
out_dir.mkdir(parents=True, exist_ok=True)

reader = next(r for r in readers() if "Smart Card" in str(r))
conn = reader.createConnection()
conn.connect()


def tx(apdu: list[int]) -> tuple[bytes, int, int]:
    assert apdu[1] in ALLOWED_INS, "only read-only commands allowed"
    data, sw1, sw2 = conn.transmit(apdu)
    return bytes(data), sw1, sw2


def select_app() -> None:
    _, sw1, sw2 = tx([0x00, 0xA4, 0x04, 0x00, len(PKI_AID), *PKI_AID])
    print(f"SELECT PKI app: {sw1:02X}{sw2:02X}")


select_app()
for name, fid in CERT_FILES.items():
    _, sw1, sw2 = tx([0x00, 0xA4, 0x02, 0x04, 0x02, fid >> 8, fid & 0xFF])
    print(f"SELECT {name} ({fid:04X}): {sw1:02X}{sw2:02X}")
    if (sw1, sw2) != (0x90, 0x00):
        continue
    cert, offset = b"", 0
    for _ in range(64):
        data, sw1, sw2 = tx([0x00, 0xB1, 0x00, 0x00, 0x04, 0x54, 0x02,
                             offset >> 8, offset & 0xFF, 0xFF])
        if len(data) > 3:
            cert += data[3:]
        if (sw1, sw2) == (0x62, 0x82) or (sw1, sw2) != (0x90, 0x00):
            break
        offset += CHUNK
    print(f"  final SW {sw1:02X}{sw2:02X}, {len(cert)} bytes")
    (out_dir / f"{name}.der").write_bytes(cert)
