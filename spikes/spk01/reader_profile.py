# SPDX-License-Identifier: GPL-3.0-or-later
# Prototipo de investigación (spike). No es código de producción.
"""SPK-01: profile a reader + DNIe v2 pair. Read-only (SELECT / READ BINARY / GET DATA).

Never sends VERIFY, MSE, PSO or any write command.
"""
import hashlib
import statistics
import sys
import time

from smartcard.scard import SCARD_CTL_CODE
from smartcard.System import readers
from smartcard.util import toHexString

PKI_AID = list(bytes.fromhex("E828BD080FD250") + b"Generic")
ALLOWED_INS = {0xA4, 0xB1, 0xCA}
CERTS = {"firma": 0x001D, "autenticacion": 0x001C, "cifrado": 0x001B}
FEATURES = {
    0x01: "VERIFY_PIN_START", 0x02: "VERIFY_PIN_FINISH", 0x03: "MODIFY_PIN_START",
    0x04: "MODIFY_PIN_FINISH", 0x05: "GET_KEY_PRESSED", 0x06: "VERIFY_PIN_DIRECT",
    0x07: "MODIFY_PIN_DIRECT", 0x08: "MCT_READER_DIRECT", 0x09: "MCT_UNIVERSAL",
    0x0A: "IFD_PIN_PROPERTIES", 0x0B: "ABORT", 0x0C: "SET_SPE_MESSAGE",
    0x0D: "VERIFY_PIN_DIRECT_APP_ID", 0x0E: "MODIFY_PIN_DIRECT_APP_ID",
    0x0F: "WRITE_DISPLAY", 0x10: "GET_KEY", 0x11: "IFD_DISPLAY_PROPERTIES",
    0x12: "GET_TLV_PROPERTIES", 0x13: "CCID_ESC_COMMAND",
}

reader = readers()[0]
print("Lector:", reader)
conn = reader.createConnection()
conn.connect()
proto = {1: "T=0", 2: "T=1"}.get(conn.getProtocol(), conn.getProtocol())
print("ATR:", toHexString(conn.getATR()))
print("Protocolo negociado:", proto)

try:
    feats = conn.control(SCARD_CTL_CODE(3400), [])
    tags = [FEATURES.get(feats[i], hex(feats[i])) for i in range(0, len(feats), 6)]
    print("Funciones PC/SC parte 10:", tags or "ninguna")
except Exception as e:  # noqa: BLE001
    print("Funciones PC/SC parte 10: error", e)


def tx(apdu):
    assert apdu[1] in ALLOWED_INS
    data, sw1, sw2 = conn.transmit(apdu)
    return bytes(data), sw1, sw2


def read_cert(fid):
    tx([0x00, 0xA4, 0x04, 0x00, len(PKI_AID), *PKI_AID])
    tx([0x00, 0xA4, 0x02, 0x04, 0x02, fid >> 8, fid & 0xFF])
    cert, off, n = b"", 0, 0
    while True:
        d, sw1, sw2 = tx([0x00, 0xB1, 0x00, 0x00, 0x04, 0x54, 0x02, off >> 8, off & 0xFF, 0xFF])
        n += 1
        cert += d[3:]
        if (sw1, sw2) != (0x90, 0x00):
            break
        off += 0xE4
    size = 4 + int.from_bytes(cert[2:4], "big")
    return cert[:size], n


for name, fid in CERTS.items():
    times = []
    for _ in range(3):
        t0 = time.perf_counter()
        cert, n = read_cert(fid)
        times.append(time.perf_counter() - t0)
    print(f"{name}: {len(cert)} B, {n} APDU, SHA-256 {hashlib.sha256(cert).hexdigest()[:16]}…, "
          f"t_mediana={statistics.median(times)*1000:.0f} ms")

# single-APDU round-trip latency
lat = []
for _ in range(20):
    t0 = time.perf_counter()
    tx([0x00, 0xA4, 0x04, 0x00, len(PKI_AID), *PKI_AID])
    lat.append(time.perf_counter() - t0)
print(f"Latencia SELECT: mediana {statistics.median(lat)*1000:.1f} ms")

# extended-length READ BINARY (Le = 0x0000 extended) to probe extended APDU support
try:
    tx([0x00, 0xA4, 0x02, 0x04, 0x02, 0x00, 0x1D])
    d, sw1, sw2 = tx([0x00, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x04, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00])
    print(f"READ BINARY extendido: SW {sw1:02X}{sw2:02X}, {len(d)} B")
except Exception as e:  # noqa: BLE001
    print("READ BINARY extendido: error", e)
sys.exit(0)
