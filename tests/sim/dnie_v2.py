# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Simulator of the DNIe v2 PKI applet, implementing the Transport protocol.

It reproduces the behaviour measured in SPK-01: 228-byte READ BINARY chunks wrapped in a
0x53 template, a PIN retry counter (63Cx / 6983), authentication that survives re-selecting
the applet and that only a power-off clears, and 6982 for PSO:CDS without a verified PIN.
"""

from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from berigna.core.token.dnie_v2 import DNIE_V2_ATR, PKI_AID

FILE_SIZE = 4096
CHUNK = 228
_DIGEST_INFO = {
    bytes.fromhex("3031300d060960864801650304020105000420"): hashes.SHA256(),
    bytes.fromhex("3041300d060960864801650304020205000430"): hashes.SHA384(),
    bytes.fromhex("3051300d060960864801650304020305000440"): hashes.SHA512(),
}


@dataclass
class DnieV2Simulator:
    files: dict[int, bytes]
    private_key: rsa.RSAPrivateKey
    pin: bytes = b"123456"
    tries_left: int = 3
    max_tries: int = 3
    atr_value: bytes = DNIE_V2_ATR
    applet_selected: bool = False
    current_file: int | None = None
    authenticated: bool = False
    mse_set: bool = False
    closed: bool = False
    headers: list[bytes] = field(default_factory=list)  # CLA INS P1 P2 only: never PIN bytes

    @property
    def atr(self) -> bytes:
        return self.atr_value

    def instructions(self) -> list[int]:
        return [header[1] for header in self.headers]

    def close(self) -> None:
        self.closed = True
        self.authenticated = False  # power-off ends the security session

    def transmit(self, apdu: bytes | bytearray) -> tuple[bytes, int]:
        if self.closed:
            raise RuntimeError("simulated card is powered off")
        apdu = bytes(apdu)
        self.headers.append(apdu[:4])
        ins, p1, p2 = apdu[1], apdu[2], apdu[3]
        data = apdu[5 : 5 + apdu[4]] if len(apdu) > 4 else b""
        handler = {
            0xA4: self._select,
            0xB1: self._read_binary,
            0x20: self._verify,
            0x22: self._mse,
            0x2A: self._pso,
        }.get(ins)
        if handler is None:
            return b"", 0x6D00
        return handler(p1, p2, data)

    def _select(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int]:
        if p1 == 0x04:
            if data != PKI_AID:
                return b"", 0x6A82
            self.applet_selected, self.current_file = True, None
            return b"", 0x9000  # authentication deliberately survives (SPK-01 §8.6)
        if p1 == 0x02 and self.applet_selected:
            fid = int.from_bytes(data, "big")
            if fid not in self.files:
                return b"", 0x6A82
            self.current_file = fid
            return b"", 0x9000
        return b"", 0x6A86

    def _read_binary(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int]:
        if self.current_file is None or len(data) != 4 or data[:2] != b"\x54\x02":
            return b"", 0x6986
        content = self.files[self.current_file].ljust(FILE_SIZE, b"\x00")
        offset = int.from_bytes(data[2:], "big")
        chunk = content[offset : offset + CHUNK]
        length = bytes([len(chunk)]) if len(chunk) < 0x80 else bytes([0x81, len(chunk)])
        sw = 0x6282 if offset + CHUNK >= FILE_SIZE else 0x9000
        return b"\x53" + length + chunk, sw

    def _verify(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int]:
        if p2 != 0x81:
            return b"", 0x6A88
        if self.tries_left == 0:
            return b"", 0x6983
        if data == self.pin:
            self.tries_left, self.authenticated = self.max_tries, True
            return b"", 0x9000
        self.tries_left -= 1
        self.authenticated = False
        return b"", 0x63C0 | self.tries_left

    def _mse(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int]:
        if (p1, p2) != (0x41, 0xB6) or data != bytes.fromhex("80018A840181"):
            return b"", 0x6A80
        self.mse_set = True
        return b"", 0x9000

    def _pso(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int]:
        if (p1, p2) != (0x9E, 0x9A):
            return b"", 0x6A86
        if not self.authenticated:
            return b"", 0x6982
        if not self.mse_set:
            return b"", 0x6985
        for prefix, algorithm in _DIGEST_INFO.items():
            if data.startswith(prefix):
                digest = data[len(prefix) :]
                signature = self.private_key.sign(
                    digest, padding.PKCS1v15(), utils.Prehashed(algorithm)
                )
                return signature, 0x9000
        return b"", 0x6A80
