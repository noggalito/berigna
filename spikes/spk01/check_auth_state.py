# SPDX-License-Identifier: GPL-3.0-or-later
# Prototipo de investigación (spike). No es código de producción.
"""SPK-01: does the DNIe v2 stay authenticated after the signing process ended?

Sends NO PIN (no VERIFY). Only SELECT + MSE:SET + PSO:CDS over a test digest.
A rejected PSO (6982) does not touch the PIN retry counter.
"""
import hashlib

from smartcard.System import readers

PKI_AID = list(bytes.fromhex("E828BD080FD250") + b"Generic")
PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
ALLOWED_INS = {0xA4, 0x22, 0x2A}

conn = readers()[0].createConnection()
conn.connect()


def tx(apdu):
    assert apdu[1] in ALLOWED_INS
    data, sw1, sw2 = conn.transmit(apdu)
    return bytes(data), f"{sw1:02X}{sw2:02X}"


print("SELECT:", tx([0x00, 0xA4, 0x04, 0x00, len(PKI_AID), *PKI_AID])[1])
print("MSE:SET:", tx([0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x8A, 0x84, 0x01, 0x81])[1])
payload = list(PREFIX + hashlib.sha256(b"berigna SPK-01 comprobacion de estado - sin valor").digest())
data, sw = tx([0x00, 0x2A, 0x9E, 0x9A, len(payload), *payload])
print("PSO:CDS sin VERIFY:", sw, f"({len(data)} B)")
print("=> la tarjeta SIGUE autenticada" if sw == "9000" else "=> la tarjeta NO está autenticada (correcto)")
