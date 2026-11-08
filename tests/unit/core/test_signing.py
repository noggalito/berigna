# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing orchestration: order of the security steps (RF-006, RF-018, RF-045, P-01)."""

import asyncio
import hashlib
import io
import logging
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import MDPPerm
from pyhanko.sign.timestamps import TimeStamper

from berigna.core.errors import (
    CertificateRevokedError,
    CertifiedDocumentError,
    LevelNotAvailableError,
    OutputExistsError,
    PdfFormatError,
    SigningCancelledError,
    SourceChangedError,
    TsaError,
    UntrustedTsaError,
)
from berigna.core.files import write_atomically
from berigna.core.formats.pades import SignatureLevel
from berigna.core.net.tsa import TsaSettings, http_timestamper
from berigna.core.signing import output_path, sign_pdf_file
from berigna.core.token.dnie_v2 import INS_PSO, INS_VERIFY, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import Indication, SignerCheck, verify_pdf
from berigna.core.validation.tsa import TrustedTimeStamper
from support.cards import make_card
from support.certified import certified_pdf
from support.net import damaged
from support.pki import Pki, build_pki, minimal_pdf
from support.prompts import PinPrompt
from support.tsa import SwitchingTimeStamper, local_tsa, make_timestamper, unknown_timestamper


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@pytest.fixture
def document(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "contrato.pdf"
    data = minimal_pdf()
    path.write_bytes(data)
    return path, hashlib.sha256(data).hexdigest()


def test_signs_and_writes_a_new_file(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    output = source.with_name("contrato-firmado.pdf")
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],
            crls=[pki.arl()],
        )
    assert result.output == output
    assert result.level is SignatureLevel.B_B
    assert result.level_note is None
    assert result.revocation_checked
    assert result.sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert len(PdfFileReader(io.BytesIO(output.read_bytes())).embedded_signatures) == 1
    assert source.read_bytes() == minimal_pdf()  # the original is never modified
    assert prompt.pins[0].wiped
    assert sorted(p.name for p in source.parent.iterdir()) == [
        "contrato-firmado.pdf",
        "contrato.pdf",
    ]


def test_without_revocation_data_the_result_says_so(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, _ = make_card(pki, "FIRMANTE SIN RED")
    prompt = PinPrompt()
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            source.with_name("f.pdf"),
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert not result.revocation_checked
    assert prompt.shown[0].only_basic_level  # the UI can warn before asking the PIN


def test_revoked_certificate_is_rejected_before_asking_the_pin(
    pki: Pki, document: tuple[Path, str]
) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE REVOCADO")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(CertificateRevokedError):
        sign_pdf_file(
            source,
            source.with_name("f.pdf"),
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
            ocsp_responses=[pki.ocsp(leaf, revoked=True)],
            crls=[pki.arl()],
        )
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()


def test_cancelling_sends_no_pin(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, _ = make_card(pki, "FIRMANTE")
    output = source.with_name("f.pdf")
    with DnieV2Token(card) as token, pytest.raises(SigningCancelledError):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=PinPrompt(answer=None),
            online=False,
        )
    assert INS_VERIFY not in card.instructions()
    assert not output.exists()


def test_damaged_pdf_is_rejected_before_asking_the_pin(pki: Pki, tmp_path: Path) -> None:
    """D-2: a file that cannot be signed must not cost the user a PIN entry."""
    source = tmp_path / "danado.pdf"
    data = b"%PDF-1.7\nesto no es un PDF completo\n"
    source.write_bytes(data)
    card, _ = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(PdfFormatError):
        sign_pdf_file(
            source,
            tmp_path / "f.pdf",
            expected_sha256=hashlib.sha256(data).hexdigest(),
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()


def test_file_changed_before_starting(pki: Pki, document: tuple[Path, str]) -> None:
    source, _ = document
    card, _ = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(SourceChangedError):
        sign_pdf_file(
            source,
            source.with_name("f.pdf"),
            expected_sha256="0" * 64,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert prompt.shown == []
    assert card.headers == []


def test_file_changed_while_the_pin_was_being_typed(pki: Pki, document: tuple[Path, str]) -> None:
    """AM-02 (TOCTOU): a change during the PIN dialog aborts before the chip signs."""
    source, sha = document
    card, _ = make_card(pki, "FIRMANTE")
    output = source.with_name("f.pdf")

    def tampering_prompt(check: SignerCheck) -> Pin:
        source.write_bytes(minimal_pdf("Contenido cambiado"))
        return Pin("123456")

    with DnieV2Token(card) as token, pytest.raises(SourceChangedError):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=tampering_prompt,
            online=False,
        )
    assert INS_PSO not in card.instructions()
    assert not output.exists()


def test_existing_output_is_never_overwritten(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    output = source.with_name("ya-existe.pdf")
    output.write_bytes(b"contenido previo")
    card, _ = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(OutputExistsError):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert output.read_bytes() == b"contenido previo"
    assert prompt.shown == []


def test_atomic_write_never_replaces_and_leaves_no_temporary_files(tmp_path: Path) -> None:
    target = tmp_path / "salida.pdf"
    write_atomically(target, b"uno")
    with pytest.raises(OutputExistsError):
        write_atomically(target, b"dos")
    assert target.read_bytes() == b"uno"
    assert [p.name for p in tmp_path.iterdir()] == ["salida.pdf"]


def test_atomic_write_replaces_only_when_asked(tmp_path: Path) -> None:
    target = tmp_path / "informe.pdf"
    target.write_bytes(b"anterior")
    write_atomically(target, b"nuevo", replace=True)
    assert target.read_bytes() == b"nuevo"
    assert [p.name for p in tmp_path.iterdir()] == ["informe.pdf"]


def test_atomic_write_detects_a_file_created_meanwhile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "carrera.pdf"
    real_link = __import__("os").link

    def racing_link(src: str, dst: Path) -> None:
        Path(dst).write_bytes(b"otro proceso")
        real_link(src, dst)

    monkeypatch.setattr("berigna.core.files.os.link", racing_link)
    with pytest.raises(OutputExistsError):
        write_atomically(target, b"mio")
    assert target.read_bytes() == b"otro proceso"
    assert [p.name for p in tmp_path.iterdir()] == ["carrera.pdf"]


# -- Levels above B-B (RF-010, RF-062) ----------------------------------------------------------


def test_signs_b_lt_with_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE B-LT")
    stamper, tsa_cert = make_timestamper(pki)
    output = source.with_name("b-lt.pdf")
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=PinPrompt(),
            level=SignatureLevel.B_LT,
            timestamper=stamper,
            online=False,
            ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa_cert)],
            crls=[pki.arl()],
        )
    assert result.level is SignatureLevel.B_LT
    assert result.level_note is None
    [report] = verify_pdf(output.read_bytes(), pki.store, online=False).signatures
    assert report.indication is Indication.TOTAL_PASSED


def _refused_before_the_pin(
    pki: Pki,
    document: tuple[Path, str],
    error: type[Exception],
    *,
    timestamper: Any = None,
    revinfo: bool = False,
) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    output = source.with_name("f.pdf")
    with DnieV2Token(card) as token, pytest.raises(error):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            level=SignatureLevel.B_T,
            timestamper=timestamper,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)] if revinfo else [],
            crls=[pki.arl()] if revinfo else [],
        )
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()
    assert not output.exists()


def test_level_above_b_b_needs_a_tsa(pki: Pki, document: tuple[Path, str]) -> None:
    _refused_before_the_pin(pki, document, LevelNotAvailableError, revinfo=True)


def test_level_above_b_b_needs_revocation_checked(pki: Pki, document: tuple[Path, str]) -> None:
    """RF-006: without revocation data only B-B may be offered."""
    stamper, _ = make_timestamper(pki)
    _refused_before_the_pin(pki, document, LevelNotAvailableError, timestamper=stamper)


def test_unreachable_tsa_is_detected_before_the_pin(pki: Pki, document: tuple[Path, str]) -> None:
    stamper, _ = make_timestamper(pki, fail_on=frozenset({1}))
    _refused_before_the_pin(pki, document, TsaError, timestamper=stamper, revinfo=True)


def test_certified_document_is_rejected_before_the_pin(tmp_path: Path, pki: Pki) -> None:
    """CU-03: the author forbade all changes; known before the PIN, not inside the signature."""
    data = certified_pdf(pki, MDPPerm.NO_CHANGES)
    source = tmp_path / "certificado.pdf"
    source.write_bytes(data)
    card, _leaf = make_card(pki, "FIRMANTE")
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(CertifiedDocumentError):
        sign_pdf_file(
            source,
            tmp_path / "salida.pdf",
            expected_sha256=hashlib.sha256(data).hexdigest(),
            token=token,
            store=pki.store,
            ask_pin=prompt,
            online=False,
        )
    assert prompt.shown == []


def test_output_path_never_reuses_a_name(tmp_path: Path) -> None:
    source = tmp_path / "contrato.pdf"
    assert output_path(source, "-firmado") == tmp_path / "contrato-firmado.pdf"
    (tmp_path / "contrato-firmado.pdf").write_bytes(b"")
    (tmp_path / "contrato-firmado-2.pdf").write_bytes(b"")
    assert output_path(source, "-firmado") == tmp_path / "contrato-firmado-3.pdf"
    other = tmp_path / "otra"
    assert output_path(source, "-f", other) == other / "contrato-f.pdf"


def test_a_damaged_answer_of_the_tsa_never_gives_a_broken_signature(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-DES-07: the probe before the PIN gets an intact answer, the time-stamp of the
    signature a damaged one. The result is a TsaError (ERR-305) or a signature that
    verifies: some damaged answers were written into the PDF, signed "B-T" and reported as
    done, and verified as TOTAL-FAILED."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    stamper, tsa = make_timestamper(pki)
    data = minimal_pdf()
    source = tmp_path / "contrato.pdf"
    source.write_bytes(data)
    damage: dict[str, int | bool] = {}

    def answer(_number: int, sent: bytes) -> bytes:
        damage["requests"] = int(damage["requests"]) + 1  # of this example
        if damage["requests"] == 1:  # the probe (pyHanko keeps it for the size of the signature)
            return sent
        return damaged(sent, int(damage["position"]), int(damage["byte"]), bool(damage["cut"]))

    with local_tsa(stamper, answer=answer) as url:

        @settings(max_examples=30, deadline=None)
        @given(position=st.integers(min_value=0), byte=st.integers(0, 255), cut=st.booleans())
        def check(position: int, byte: int, cut: bool) -> None:
            damage.update(position=position, byte=byte, cut=cut, requests=0)
            card, leaf = make_card(pki, "FIRMANTE CON TSA DAÑADA")  # a card powers off when closed
            revinfo = {"ocsp_responses": [pki.ocsp(leaf), pki.ocsp(tsa)], "crls": [pki.arl()]}
            output = tmp_path / f"firmado-{position}-{byte}-{cut}.pdf"
            output.unlink(missing_ok=True)
            with DnieV2Token(card) as token:
                try:
                    sign_pdf_file(
                        source,
                        output,
                        expected_sha256=hashlib.sha256(data).hexdigest(),
                        token=token,
                        store=pki.store,
                        ask_pin=PinPrompt(),
                        level=SignatureLevel.B_T,
                        timestamper=http_timestamper(TsaSettings(url, timeout=5)),
                        online=False,
                        **revinfo,  # type: ignore[arg-type]
                    )
                except TsaError:
                    assert not output.exists()
                    return
            [report] = verify_pdf(
                output.read_bytes(), pki.store, online=False, **revinfo
            ).signatures  # type: ignore[arg-type]
            assert report.indication is Indication.TOTAL_PASSED

        check()


# -- R-DES-20: the TSA is trusted before its time-stamp is written ----------------------------


def test_a_tsa_that_is_not_trusted_is_refused_before_the_pin(
    pki: Pki, document: tuple[Path, str]
) -> None:
    """Its certificate leads to no anchor of the store: ERR-314, a level not available (the
    UI offers B-B), known with the test token, before the PIN."""
    _refused_before_the_pin(
        pki, document, UntrustedTsaError, timestamper=unknown_timestamper(), revinfo=True
    )
    assert issubclass(UntrustedTsaError, LevelNotAvailableError)  # the UI offers B-B


def test_a_revoked_tsa_is_refused_before_the_pin(pki: Pki, document: tuple[Path, str]) -> None:
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, tsa = make_timestamper(pki)
    prompt = PinPrompt()
    with DnieV2Token(card) as token, pytest.raises(UntrustedTsaError, match="revoked"):
        sign_pdf_file(
            source,
            source.with_name("f.pdf"),
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=prompt,
            level=SignatureLevel.B_T,
            timestamper=stamper,
            online=False,
            ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa, revoked=True)],
            crls=[pki.arl()],
        )
    assert prompt.shown == []
    assert INS_VERIFY not in card.instructions()


def test_a_trusted_tsa_without_revocation_data_still_stamps(
    pki: Pki, document: tuple[Path, str], caplog: pytest.LogCaptureFixture
) -> None:
    """Decision of 2026-11-08: revocation of the TSA that cannot be established is logged,
    not a reason to refuse the time-stamp."""
    caplog.set_level(logging.DEBUG, logger="berigna")  # offline it is only a debug line
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, _tsa = make_timestamper(pki)
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            source.with_name("b-t.pdf"),
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=PinPrompt(),
            level=SignatureLevel.B_T,
            timestamper=stamper,
            online=False,
            ocsp_responses=[pki.ocsp(leaf)],  # none for the TSA
            crls=[pki.arl()],
        )
    assert result.level is SignatureLevel.B_T
    assert any("revocation of the TSA certificate" in r.message for r in caplog.records)


def test_a_time_stamp_from_a_tsa_that_is_not_trusted_is_never_written(
    pki: Pki, document: tuple[Path, str]
) -> None:
    """The test token passed, the real one comes from another TSA: refused after the PIN,
    before anything is written."""
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, tsa = make_timestamper(pki)
    output = source.with_name("f.pdf")
    with DnieV2Token(card) as token, pytest.raises(UntrustedTsaError):
        sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=PinPrompt(),
            level=SignatureLevel.B_T,
            timestamper=SwitchingTimeStamper(stamper, unknown_timestamper()),
            online=False,
            ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
            crls=[pki.arl()],
        )
    assert INS_PSO in card.instructions()  # signed by the card, then refused
    assert not output.exists()


def test_each_tsa_certificate_is_validated_once(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    from berigna.core.validation import tsa as module

    calls: list[object] = []
    real_check = module.check_tsa

    async def counted(*args: Any, **kwargs: Any) -> None:
        calls.append(args[0])
        await real_check(*args, **kwargs)

    monkeypatch.setattr(module, "check_tsa", counted)
    stamper, tsa = make_timestamper(pki)
    trusted = TrustedTimeStamper(stamper, pki.store, online=False, ocsp_responses=[pki.ocsp(tsa)])
    trusted.check_now()
    digest = hashlib.sha256(b"x").digest()
    for _ in range(3):
        asyncio.run(trusted.async_timestamp(digest, "sha256"))
    assert len(calls) == 1


def _crl_revoking(pki: Pki, certificate: Any) -> bytes:
    """A CRL of the test CA that revokes ``certificate``."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    from support.pki import NOW

    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.ca.subject)
        .last_update(NOW - dt.timedelta(hours=1))
        .next_update(NOW + dt.timedelta(days=7))
        .add_extension(x509.CRLNumber(1), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pki.ca_key.public_key()),
            critical=False,
        )
        .add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(certificate.serial_number)
            .revocation_date(NOW - dt.timedelta(days=1))
            .build()
        )
        .sign(pki.ca_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def test_a_tsa_revoked_in_its_crl_is_refused(pki: Pki) -> None:
    """Review of R-DES-20: a TSA may publish only a CRL. With OCSP required, as for the
    DNIe, a CRL was never looked at and a revoked TSA passed."""
    from berigna.core.certs import to_asn1
    from berigna.core.validation.tsa import check_tsa

    _stamper, tsa = make_timestamper(pki)
    with pytest.raises(UntrustedTsaError, match="revoked"):
        asyncio.run(
            check_tsa(
                to_asn1(tsa), pki.store, online=False, crls=[_crl_revoking(pki, tsa), pki.arl()]
            )
        )


class _WithoutCertificate(TimeStamper):
    """A TSA that ignores cert_req: its token carries no certificate."""

    def __init__(self, inner: TimeStamper) -> None:
        super().__init__()
        self._inner = inner

    async def async_dummy_response(self, md_algorithm: str) -> Any:
        from asn1crypto import cms

        token = await self._inner.async_dummy_response(md_algorithm)
        stripped = token.copy()
        content = stripped["content"]
        content["certificates"] = cms.CertificateSet([])
        return cms.ContentInfo.load(stripped.dump(force=True))


def test_a_token_without_its_tsa_certificate_is_a_tsa_error(pki: Pki) -> None:
    """Not ERR-000 (nor a dead thread in "Test"): the token is not a valid one."""
    stamper, _tsa = make_timestamper(pki)
    trusted = TrustedTimeStamper(_WithoutCertificate(stamper), pki.store, online=False)
    with pytest.raises(TsaError, match="does not carry"):
        trusted.check_now()


def _slow_online_check(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """check_tsa that hangs when it may use the network (a revocation service that does
    not answer) and runs as usual without it; returns the ``online`` of each call."""
    from berigna.core.validation import tsa as module

    calls: list[bool] = []
    real_check = module.check_tsa

    async def slow(*args: Any, online: bool, **kwargs: Any) -> None:
        calls.append(online)
        if online:  # the abandoned thread wakes later and does nothing (no log, no state)
            await asyncio.sleep(1)
            return
        await real_check(*args, online=online, **kwargs)

    monkeypatch.setattr(module, "check_tsa", slow)
    return calls


def test_a_trusted_tsa_whose_revocation_does_not_answer_in_time_still_stamps(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Review of R-DES-20: the deadline before the PIN must not turn a slow revocation
    service into ERR-305 (decision of 2026-11-08). Past it, the chain is checked offline."""
    calls = _slow_online_check(monkeypatch)
    stamper, _tsa = make_timestamper(pki)
    asyncio.run(stamper.async_dummy_response("sha256"))  # what the probe leaves
    trusted = TrustedTimeStamper(stamper, pki.store, online=True)
    trusted.check_now(deadline=0.2)
    assert calls == [True, False]
    assert any("within 0.2 s" in r.message for r in caplog.records)
    digest = hashlib.sha256(b"x").digest()
    asyncio.run(trusted.async_timestamp(digest, "sha256"))  # validated once: no new check
    assert calls == [True, False]


def test_a_tsa_that_is_not_trusted_is_refused_even_past_the_deadline(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    _slow_online_check(monkeypatch)
    stamper = unknown_timestamper()
    asyncio.run(stamper.async_dummy_response("sha256"))
    with pytest.raises(UntrustedTsaError):
        TrustedTimeStamper(stamper, pki.store, online=True).check_now(deadline=0.2)


def test_an_archive_time_stamp_from_a_tsa_that_is_not_trusted_keeps_the_b_lt(
    pki: Pki, document: tuple[Path, str]
) -> None:
    """Review of R-DES-20: the signature time-stamp comes from the trusted TSA, the document
    time-stamp of B-LTA from another. The signature made with the PIN is kept, at B-LT with
    its note, as with any service that fails after the card has signed."""
    source, sha = document
    card, leaf = make_card(pki, "FIRMANTE B-LTA")
    stamper, tsa = make_timestamper(pki)
    output = source.with_name("b-lta.pdf")
    with DnieV2Token(card) as token:
        result = sign_pdf_file(
            source,
            output,
            expected_sha256=sha,
            token=token,
            store=pki.store,
            ask_pin=PinPrompt(),
            level=SignatureLevel.B_LTA,
            timestamper=SwitchingTimeStamper(stamper, unknown_timestamper(), first_stamps=1),
            online=False,
            ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa)],
            crls=[pki.arl()],
        )
    assert result.level is SignatureLevel.B_LT
    assert result.level_note is not None
    assert output.exists()


def test_any_failure_while_checking_the_tsa_is_a_tsa_error(pki: Pki) -> None:
    """Review of R-DES-20: whatever the time-stamper raises, the step before the PIN, "Test"
    and the diagnosis get ERR-305, never an unexpected error (ERR-000)."""

    class Broken(TimeStamper):
        async def async_dummy_response(self, md_algorithm: str) -> Any:
            raise RuntimeError("the cache of the test token is gone")

    with pytest.raises(TsaError, match="could not be checked"):
        TrustedTimeStamper(Broken(), pki.store, online=True).check_now()
