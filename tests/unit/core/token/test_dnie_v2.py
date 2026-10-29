# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""DnieV2Token against the applet simulator (PR-TOK-02 to PR-TOK-06, PR-SEG-05)."""

import hashlib
import math

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from hypothesis import given
from hypothesis import strategies as st

from berigna.core.errors import (
    CertificateUsageError,
    InstructionNotAllowedError,
    NotAuthenticatedError,
    PinBlockedError,
    PinIncorrectError,
    UnsupportedCardError,
)
from berigna.core.token.dnie_v2 import (
    INS_PSO,
    INS_READ_BINARY_ODD,
    INS_VERIFY,
    CertificateSlot,
    DnieV2Token,
    _ber_length,
)
from berigna.core.token.pin import Pin
from sim.dnie_v2 import CHUNK, FILE_SIZE, DnieV2Simulator


def test_rejects_a_card_that_is_not_a_dnie_v2(card: DnieV2Simulator) -> None:
    card.atr_value = bytes.fromhex("3B00")
    with pytest.raises(UnsupportedCardError):
        DnieV2Token(card)
    assert card.closed


def test_reads_the_signing_certificate_stopping_at_der_length(
    card: DnieV2Simulator, card_files: dict[int, bytes]
) -> None:
    """PR-TOK-02 and RF-003: same bytes as the card, without reading the whole 4 KiB file."""
    expected = card_files[CertificateSlot.SIGNATURE.value]
    token = DnieV2Token(card)
    assert token.read_certificate() == expected
    reads = card.instructions().count(INS_READ_BINARY_ODD)
    assert reads == math.ceil(len(expected) / CHUNK)
    assert reads < math.ceil(FILE_SIZE / CHUNK)


def test_certificates_are_cached(card: DnieV2Simulator) -> None:
    token = DnieV2Token(card)
    token.read_certificate()
    sent = len(card.headers)
    token.read_certificate()
    assert len(card.headers) == sent


def test_signing_certificate_must_have_non_repudiation(
    card: DnieV2Simulator, card_files: dict[int, bytes]
) -> None:
    """PR-TOK-03/04 and RF-004: never sign with a certificate lacking nonRepudiation."""
    assert DnieV2Token(card).signing_certificate() is not None
    card.files[CertificateSlot.SIGNATURE.value] = card_files[CertificateSlot.AUTHENTICATION.value]
    with pytest.raises(CertificateUsageError):
        DnieV2Token(card).signing_certificate()


def test_verify_then_sign_produces_a_valid_signature(
    card: DnieV2Simulator, signing_key: rsa.RSAPrivateKey
) -> None:
    pin = Pin("123456")
    digest = hashlib.sha256(b"documento").digest()
    with DnieV2Token(card) as token:
        token.verify_pin(pin)
        signature = token.sign_digest(digest)
    signing_key.public_key().verify(
        signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    assert pin.wiped
    assert card.closed


def test_one_pin_serves_several_signatures(card: DnieV2Simulator) -> None:
    """RF-040 on the DNIe v2: the VERIFY persists between PSO:CDS (SPK-01 §8.6)."""
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        for n in range(3):
            token.sign_digest(hashlib.sha256(bytes([n])).digest())
    assert card.instructions().count(INS_VERIFY) == 1
    assert card.instructions().count(INS_PSO) == 3


@pytest.mark.parametrize("algorithm", ["sha384", "sha512"])
def test_other_digest_algorithms(
    card: DnieV2Simulator, signing_key: rsa.RSAPrivateKey, algorithm: str
) -> None:
    digest = hashlib.new(algorithm, b"x").digest()
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        signature = token.sign_digest(digest, algorithm)  # type: ignore[arg-type]
    hash_algorithm = {"sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[algorithm]
    signing_key.public_key().verify(
        signature, digest, padding.PKCS1v15(), utils.Prehashed(hash_algorithm)
    )


def test_rejects_a_digest_of_the_wrong_length(card: DnieV2Simulator) -> None:
    with DnieV2Token(card) as token, pytest.raises(ValueError, match="digest length"):
        token.sign_digest(b"\x00" * 20)


def test_signing_without_pin_sends_nothing_to_the_card(card: DnieV2Simulator) -> None:
    with DnieV2Token(card) as token, pytest.raises(NotAuthenticatedError):
        token.sign_digest(hashlib.sha256(b"x").digest())
    assert INS_PSO not in card.instructions()


def test_card_side_loss_of_authentication_is_reported(card: DnieV2Simulator) -> None:
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        card.authenticated = False
        with pytest.raises(NotAuthenticatedError):
            token.sign_digest(hashlib.sha256(b"x").digest())


def test_wrong_pin_reports_remaining_tries_and_is_not_retried(card: DnieV2Simulator) -> None:
    """PR-TOK-05, P-06: a single VERIFY per call, remaining tries from 63Cx."""
    pin = Pin("000000")
    with DnieV2Token(card) as token, pytest.raises(PinIncorrectError) as raised:
        token.verify_pin(pin)
    assert raised.value.remaining_tries == 2
    assert card.instructions().count(INS_VERIFY) == 1
    assert pin.wiped


def test_blocked_pin(card: DnieV2Simulator) -> None:
    card.tries_left = 0
    with DnieV2Token(card) as token, pytest.raises(PinBlockedError):
        token.verify_pin(Pin("123456"))


def test_instructions_outside_the_allow_list_never_reach_the_card(
    card: DnieV2Simulator,
) -> None:
    """PR-TOK-06, AM-19: e.g. CHANGE REFERENCE DATA (0x24) or a GlobalPlatform command."""
    token = DnieV2Token(card)
    refused = [
        bytes([0x00, 0x24, 0x00, 0x81, 0x01, 0x30]),  # CHANGE REFERENCE DATA
        bytes([0x80, 0xCA, 0x9F, 0x7F, 0x00]),  # GlobalPlatform GET DATA
        b"\x00",
        bytes([0x00, 0xA4, 0x04, 0x00, 0x08]) + bytes.fromhex("A000000151000000"),  # ISD
        bytes([0x00, 0xA4, 0x04, 0x00, 0x07]) + bytes.fromhex("A0000002471001"),  # ICAO
        bytes([0x00, 0xA4, 0x02, 0x04, 0x02, 0x3F, 0x00]),  # a file that is not a cert
        bytes([0x00, 0x20, 0x00, 0x83, 0x04]) + b"1234",  # encryption PIN reference
        bytes([0x00, 0x20, 0x00, 0x81, 0x04]) + b"12",  # Lc does not match the body
        bytes([0x00, 0x22, 0x41, 0xB6, 0x06]) + bytes.fromhex("80018A840183"),  # other key
        bytes([0x00, 0x2A, 0x9E, 0x9A, 0x04]) + b"junk",  # raw data instead of DigestInfo
        bytes([0x00, 0xB1, 0x00, 0x00, 0x04, 0x54, 0x01, 0x00, 0x00, 0xFF]),
    ]
    for apdu in refused:
        with pytest.raises(InstructionNotAllowedError):
            token._transmit(apdu)
    assert card.headers == []


@given(st.binary(max_size=80))
def test_random_apdus_are_refused_or_exactly_allowed(apdu: bytes) -> None:
    """Fuzzing of the allow-list (P-4): anything accepted must be a well-formed allowed form."""
    from berigna.core.token.dnie_v2 import PKI_AID, _check_allowed

    try:
        _check_allowed(apdu)
    except InstructionNotAllowedError:
        return
    assert apdu[0] == 0x00
    assert len(apdu) == 5 + apdu[4]
    assert apdu[1] in {0xA4, 0xB1, 0x20, 0x22, 0x2A}
    if apdu[1] == 0xA4 and apdu[2] == 0x04:
        assert apdu[5:] == PKI_AID


def test_session_is_closed_when_the_block_fails(card: DnieV2Simulator) -> None:
    """PR-SEG-05: after an error the card is powered off and no longer authenticated."""

    def sign_then_fail() -> None:
        with DnieV2Token(card) as token:
            token.verify_pin(Pin("123456"))
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        sign_then_fail()
    assert card.closed
    assert not card.authenticated


@given(st.integers(min_value=0, max_value=0xFFFFFF))
def test_ber_length_round_trip(length: int) -> None:
    if length < 0x80:
        encoded = bytes([length])
    else:
        body = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(body)]) + body
    assert _ber_length(b"\x30" + encoded, 1) == (length, 1 + len(encoded))


# -- malformed or unexpected card answers --------------------------------------------------


class _Scripted(DnieV2Simulator):
    """Simulator whose answers for one instruction are replaced by a fixed response."""

    override: dict[int, tuple[bytes, int]]

    def transmit(self, apdu: bytes | bytearray) -> tuple[bytes, int]:
        if apdu[1] in self.override:
            self.headers.append(bytes(apdu[:4]))
            return self.override[apdu[1]]
        return super().transmit(apdu)


def _scripted(card: DnieV2Simulator, ins: int, answer: tuple[bytes, int]) -> _Scripted:
    scripted = _Scripted(files=card.files, private_key=card.private_key)
    scripted.override = {ins: answer}
    return scripted


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        ((b"", 0x6A82), "READ BINARY"),
        ((b"\x00\x01", 0x9000), "unexpected READ BINARY"),
        ((b"\x53\x04\x04\x00\x00\x00", 0x9000), "does not hold DER"),
        ((b"\x53\x04\x30\x82\x10\x00", 0x6282), "ended early"),
        ((b"\x53\x85", 0x9000), "unsupported BER"),
        ((b"\x53", 0x9000), "truncated BER"),
    ],
)
def test_malformed_certificate_reads_are_rejected(
    card: DnieV2Simulator, answer: tuple[bytes, int], message: str
) -> None:
    from berigna.core.errors import CardCommunicationError

    with pytest.raises(CardCommunicationError, match=message):
        DnieV2Token(_scripted(card, INS_READ_BINARY_ODD, answer)).read_certificate()


def test_unexpected_answers_to_select_verify_and_mse(card: DnieV2Simulator) -> None:
    from berigna.core.errors import CardCommunicationError
    from berigna.core.token.dnie_v2 import INS_MSE, INS_SELECT

    with pytest.raises(CardCommunicationError, match="SELECT applet"):
        DnieV2Token(_scripted(card, INS_SELECT, (b"", 0x6A82))).read_certificate()
    with pytest.raises(CardCommunicationError, match="VERIFY") as raised:
        DnieV2Token(_scripted(card, INS_VERIFY, (b"", 0x6A88))).verify_pin(Pin("123456"))
    assert raised.value.status_word == 0x6A88
    token = DnieV2Token(_scripted(card, INS_MSE, (b"", 0x6A80)))
    token.verify_pin(Pin("123456"))
    assert token.authenticated
    with pytest.raises(CardCommunicationError, match="MSE:SET"):
        token.sign_digest(hashlib.sha256(b"x").digest())


def test_signing_certificate_without_key_usage(card: DnieV2Simulator) -> None:
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SIN KU")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(card.private_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(card.private_key, hashes.SHA256())
    )
    card.files[CertificateSlot.SIGNATURE.value] = cert.public_bytes(serialization.Encoding.DER)
    with pytest.raises(CertificateUsageError, match="without keyUsage"):
        DnieV2Token(card).signing_certificate()


def test_irregular_read_chunks_are_rejected(card: DnieV2Simulator) -> None:
    """O-4: a non-final chunk shorter than 228 bytes means the card skipped or overlapped data."""
    from berigna.core.errors import CardCommunicationError

    short_chunk = (b"\x53\x64\x30\x82\x09\x00" + bytes(98), 0x9000)
    with pytest.raises(CardCommunicationError, match="irregular"):
        DnieV2Token(_scripted(card, INS_READ_BINARY_ODD, short_chunk)).read_certificate()


def test_probe_alive(card: DnieV2Simulator) -> None:
    with DnieV2Token(card) as token:
        assert token.probe_alive()
        assert not token.authenticated


class _Flaky(DnieV2Simulator):
    """Fails the first ``failures`` exchanges of the listed instructions transiently."""

    flaky: dict[int, int]

    def transmit(self, apdu: bytes | bytearray) -> tuple[bytes, int]:
        from berigna.core.errors import CardTransientError

        if self.flaky.get(apdu[1], 0) > 0:
            self.flaky[apdu[1]] -= 1
            self.headers.append(bytes(apdu[:4]))
            raise CardTransientError("simulated SCARD_E_NOT_TRANSACTED")
        return super().transmit(apdu)


def _flaky(card: DnieV2Simulator, *instructions: int, failures: int = 1) -> _Flaky:
    flaky = _Flaky(files=card.files, private_key=card.private_key)
    flaky.flaky = dict.fromkeys(instructions, failures)
    return flaky


def test_transient_failures_of_select_and_read_are_retried(card: DnieV2Simulator) -> None:
    """Up to two retries with growing pauses (50 ms, 150 ms) for side-effect-free commands."""
    from berigna.core.token.dnie_v2 import INS_SELECT

    pauses: list[float] = []
    flaky = _flaky(card, INS_SELECT, INS_READ_BINARY_ODD, failures=2)
    der = DnieV2Token(flaky, sleep=pauses.append).read_certificate()
    assert der == card.files[CertificateSlot.SIGNATURE.value]
    assert pauses == [0.05, 0.15, 0.05, 0.15]


def test_persistent_transient_failure_gives_up_and_closes(card: DnieV2Simulator) -> None:
    from berigna.core.errors import CardTransientError
    from berigna.core.token.dnie_v2 import INS_SELECT

    flaky = _flaky(card, INS_SELECT, failures=3)
    with pytest.raises(CardTransientError):
        DnieV2Token(flaky, sleep=lambda _: None).read_certificate()
    assert flaky.instructions().count(INS_SELECT) == 3
    assert flaky.closed


def test_transient_failure_of_verify_is_never_retried(card: DnieV2Simulator) -> None:
    """P-06: the PIN may or may not have reached the card; resending could cost a try."""
    from berigna.core.errors import CardTransientError

    flaky = _flaky(card, INS_VERIFY)
    pin = Pin("123456")
    with pytest.raises(CardTransientError):
        DnieV2Token(flaky, sleep=lambda _: pytest.fail("VERIFY must not wait to retry")).verify_pin(
            pin
        )
    assert flaky.instructions().count(INS_VERIFY) == 1
    assert flaky.closed
    assert pin.wiped


def test_transient_failure_of_pso_is_never_retried(card: DnieV2Simulator) -> None:
    from berigna.core.errors import CardTransientError

    flaky = _flaky(card, INS_PSO)
    token = DnieV2Token(flaky)
    token.verify_pin(Pin("123456"))
    with pytest.raises(CardTransientError):
        token.sign_digest(hashlib.sha256(b"x").digest())
    assert flaky.instructions().count(INS_PSO) == 1
    assert flaky.closed
