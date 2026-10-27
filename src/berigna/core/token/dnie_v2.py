# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""APDU driver for the PKI applet of the Peruvian DNIe v2 (ADR-0012, SPK-01 §8.4 and §8.6).

Rules enforced here:

- Only the exact forms of SELECT, READ BINARY, VERIFY, MSE:SET and PSO:CDS that this driver
  uses may reach the card (:func:`_check_allowed`); anything else is rejected before
  transmission (AM-19).
- The PIN is sent at most once per call, never retried, and its buffers are wiped.
- The session is closed by the transport, which powers the card off.

Deliberate limits (see arquitectura-general §3.2):

- :meth:`DnieV2Token.signing_certificate` only checks the key usage; validity, chain and
  revocation belong to the validation layer (RF-006), not to the driver.
- PSO:CDS is sent without ``Le``, as verified on the real card (SPK-01 §8.6, HIL 2026-10-27).
- The PIN length limit (255) is the APDU limit; the card enforces its own policy.
"""

import enum
import hashlib
import time
from collections.abc import Callable
from types import TracebackType
from typing import Final, Self

from cryptography import x509

from berigna.core.errors import (
    CardCommunicationError,
    CardTransientError,
    CertificateUsageError,
    InstructionNotAllowedError,
    NotAuthenticatedError,
    PinBlockedError,
    PinIncorrectError,
    UnsupportedCardError,
)
from berigna.core.token.base import HashAlgorithmName
from berigna.core.token.pin import Pin
from berigna.core.token.transport import Transport

DNIE_V2_ATR: Final = bytes.fromhex("3BDC18FF8191FE1FC38073C821136605036351000250")
PKI_AID: Final = bytes.fromhex("E828BD080FD250") + b"Generic"

INS_SELECT: Final = 0xA4
INS_READ_BINARY_ODD: Final = 0xB1
INS_VERIFY: Final = 0x20
INS_MSE: Final = 0x22
INS_PSO: Final = 0x2A

SW_OK: Final = 0x9000
SW_END_OF_FILE: Final = 0x6282
SW_SECURITY_NOT_SATISFIED: Final = 0x6982
SW_PIN_BLOCKED: Final = 0x6983

PIN_REFERENCE_SIGNATURE: Final = 0x81
READ_CHUNK: Final = 0xE4  # the applet returns at most 228 data bytes per READ BINARY

# MSE:SET for digital signature with key 0x81, padding done by the card (SPK-01 §8.4).
_MSE_SET_SIGNATURE: Final = bytes.fromhex("002241B60680018A840181")

_DIGEST_INFO_PREFIX: Final[dict[HashAlgorithmName, bytes]] = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


class CertificateSlot(enum.Enum):
    SIGNATURE = 0x001D
    AUTHENTICATION = 0x001C
    ENCRYPTION = 0x001B


# Commands without side effects on the card: the only ones retried after a transient PC/SC
# failure. VERIFY must never be resent (it could consume a PIN try, P-06), nor MSE/PSO.
_RETRYABLE_INSTRUCTIONS: Final = frozenset({INS_SELECT, INS_READ_BINARY_ODD})
_RETRY_DELAYS: Final = (0.05, 0.15)  # seconds; the card may need a moment after power-up

_CERTIFICATE_FILE_IDS: Final = frozenset(slot.value.to_bytes(2, "big") for slot in CertificateSlot)


def is_dnie_v2(atr: bytes) -> bool:
    return atr == DNIE_V2_ATR


def _check_allowed(apdu: bytes | bytearray) -> None:
    """Refuse any APDU that is not one of the exact commands this driver sends (AM-19).

    VERIFY bodies are never copied or inspected: only their declared length is checked.
    """
    if len(apdu) < 5 or apdu[0] != 0x00:
        raise InstructionNotAllowedError("malformed APDU or unexpected class byte")
    ins, p1, p2, lc = apdu[1], apdu[2], apdu[3], apdu[4]
    if ins == INS_VERIFY:
        allowed = (p1, p2) == (0x00, PIN_REFERENCE_SIGNATURE) and lc >= 1 and len(apdu) == 5 + lc
    elif ins == INS_SELECT:
        body = bytes(apdu[5:])
        allowed = len(body) == lc and (
            ((p1, p2) == (0x04, 0x00) and body == PKI_AID)
            or ((p1, p2) == (0x02, 0x04) and body in _CERTIFICATE_FILE_IDS)
        )
    elif ins == INS_READ_BINARY_ODD:
        allowed = (
            (p1, p2) == (0x00, 0x00)
            and lc == 4
            and len(apdu) == 10
            and bytes(apdu[5:7]) == b"\x54\x02"
            and apdu[9] == 0xFF
        )
    elif ins == INS_MSE:
        allowed = bytes(apdu) == _MSE_SET_SIGNATURE
    elif ins == INS_PSO:
        body = bytes(apdu[5:])
        allowed = (
            (p1, p2) == (0x9E, 0x9A)
            and len(body) == lc
            and any(
                body.startswith(prefix) and lc == len(prefix) + prefix[-1]
                for prefix in _DIGEST_INFO_PREFIX.values()
            )
        )
    else:
        allowed = False
    if not allowed:
        raise InstructionNotAllowedError(
            f"APDU {ins:02X} {p1:02X} {p2:02X} is not in the driver's allow-list"
        )


def _ber_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a BER length at ``offset``; return ``(length, offset after the length)``."""
    if offset >= len(data):
        raise CardCommunicationError("truncated BER length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 3 or offset + 1 + count > len(data):
        raise CardCommunicationError("unsupported BER length")
    return int.from_bytes(data[offset + 1 : offset + 1 + count], "big"), offset + 1 + count


def _check_sw(status_word: int, operation: str) -> None:
    if status_word != SW_OK:
        raise CardCommunicationError(f"{operation} failed: {status_word:04X}", status_word)


class DnieV2Token:
    """:class:`~berigna.core.token.base.TokenSigner` implementation for the DNIe v2."""

    def __init__(self, transport: Transport, sleep: Callable[[float], None] = time.sleep) -> None:
        if not is_dnie_v2(transport.atr):
            transport.close()
            raise UnsupportedCardError(f"not a DNIe v2: ATR {transport.atr.hex().upper()}")
        self._transport = transport
        self._sleep = sleep
        self._authenticated = False
        self._certificates: dict[CertificateSlot, bytes] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- transport -----------------------------------------------------------------------

    def _transmit(self, apdu: bytes | bytearray) -> tuple[bytes, int]:
        _check_allowed(apdu)
        delays = _RETRY_DELAYS if apdu[1] in _RETRYABLE_INSTRUCTIONS else ()
        for delay in (*delays, None):
            try:
                return self._transport.transmit(apdu)
            except CardTransientError:
                if delay is None:
                    self.close()
                    raise
                self._sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover

    @property
    def authenticated(self) -> bool:
        """Whether this session believes the PIN was verified (the card has the last word)."""
        return self._authenticated

    def probe_alive(self) -> bool:
        """Select the PKI applet; True if the card answers 9000 (diagnostics, RF-007)."""
        _, sw = self._transmit(bytes([0x00, INS_SELECT, 0x04, 0x00, len(PKI_AID)]) + PKI_AID)
        return sw == SW_OK

    def _select_applet(self) -> None:
        _, sw = self._transmit(bytes([0x00, INS_SELECT, 0x04, 0x00, len(PKI_AID)]) + PKI_AID)
        _check_sw(sw, "SELECT applet")

    # -- certificates --------------------------------------------------------------------

    def read_certificate(self, slot: CertificateSlot = CertificateSlot.SIGNATURE) -> bytes:
        """Return the DER certificate of ``slot``; reads stop at the DER length (RF-003)."""
        if slot in self._certificates:
            return self._certificates[slot]
        self._select_applet()
        fid = slot.value.to_bytes(2, "big")
        _, sw = self._transmit(bytes([0x00, INS_SELECT, 0x02, 0x04, 0x02]) + fid)
        _check_sw(sw, f"SELECT {slot.name}")

        content = bytearray()
        total: int | None = None
        offset = 0
        while total is None or len(content) < total:
            command = bytes([0x00, INS_READ_BINARY_ODD, 0x00, 0x00, 0x04, 0x54, 0x02])
            data, sw = self._transmit(command + offset.to_bytes(2, "big") + b"\xff")
            if sw not in (SW_OK, SW_END_OF_FILE):
                _check_sw(sw, f"READ BINARY {slot.name}")
            if not data or data[0] != 0x53:
                raise CardCommunicationError("unexpected READ BINARY response")
            length, start = _ber_length(data, 1)
            content += data[start : start + length]
            if total is None and len(content) >= 4:
                if content[0] != 0x30:
                    raise CardCommunicationError("certificate file does not hold DER")
                body_length, header_end = _ber_length(bytes(content), 1)
                total = header_end + body_length
            if sw == SW_END_OF_FILE or length == 0:
                break
            if length != READ_CHUNK and (total is None or len(content) < total):
                raise CardCommunicationError("irregular READ BINARY chunk")
            offset += length
        if total is None or len(content) < total:
            raise CardCommunicationError("certificate file ended early")
        der = bytes(content[:total])
        self._certificates[slot] = der
        return der

    def signing_certificate(self) -> x509.Certificate:
        cert = x509.load_der_x509_certificate(self.read_certificate(CertificateSlot.SIGNATURE))
        try:
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound as exc:
            raise CertificateUsageError("signing certificate without keyUsage") from exc
        if not key_usage.content_commitment:
            raise CertificateUsageError("signing certificate lacks nonRepudiation")
        return cert

    # -- PIN and signature ---------------------------------------------------------------

    def verify_pin(self, pin: Pin) -> None:
        apdu = bytearray()
        try:
            self._select_applet()
            secret = pin.buffer()
            apdu += bytes([0x00, INS_VERIFY, 0x00, PIN_REFERENCE_SIGNATURE, len(secret)])
            apdu += secret
            _, sw = self._transmit(apdu)
        finally:
            for i in range(len(apdu)):
                apdu[i] = 0
            pin.wipe()
        if sw == SW_OK:
            self._authenticated = True
            return
        self._authenticated = False
        if sw & 0xFFF0 == 0x63C0:
            raise PinIncorrectError(sw & 0x000F)
        if sw == SW_PIN_BLOCKED:
            raise PinBlockedError("PIN blocked")
        _check_sw(sw, "VERIFY")

    def sign_digest(self, digest: bytes, algorithm: HashAlgorithmName = "sha256") -> bytes:
        if len(digest) != hashlib.new(algorithm).digest_size:
            raise ValueError(f"digest length does not match {algorithm}")
        if not self._authenticated:
            raise NotAuthenticatedError("PIN not verified in this session")
        _, sw = self._transmit(_MSE_SET_SIGNATURE)
        _check_sw(sw, "MSE:SET")
        digest_info = _DIGEST_INFO_PREFIX[algorithm] + digest
        signature, sw = self._transmit(
            bytes([0x00, INS_PSO, 0x9E, 0x9A, len(digest_info)]) + digest_info
        )
        if sw == SW_SECURITY_NOT_SATISFIED:
            self._authenticated = False
            raise NotAuthenticatedError("card reports security status not satisfied")
        _check_sw(sw, "PSO:CDS")
        return signature

    def close(self) -> None:
        self._authenticated = False
        self._transport.close()
