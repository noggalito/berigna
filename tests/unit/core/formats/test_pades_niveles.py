# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""PAdES B-T, B-LT and B-LTA with the card simulator and a test TSA (RF-010, RF-062)."""

from dataclasses import dataclass

import pytest
from cryptography import x509

from berigna.core.errors import TsaError
from berigna.core.formats.pades import PadesResult, SignatureLevel, sign_pdf_pades
from berigna.core.token.dnie_v2 import INS_PSO, DnieV2Token
from berigna.core.token.pin import Pin
from berigna.core.validation import Indication, signing_validation_context, verify_pdf
from support.cards import make_card
from support.pki import Pki, build_pki, minimal_pdf
from support.tsa import FlakyTimeStamper, make_timestamper, unknown_timestamper


@pytest.fixture(scope="module")
def pki() -> Pki:
    return build_pki()


@dataclass
class Signed:
    result: PadesResult
    leaf: x509.Certificate
    tsa: x509.Certificate
    stamper: FlakyTimeStamper
    card_signatures: int


def _sign(
    pki: Pki,
    level: SignatureLevel,
    *,
    fail_on: frozenset[int] = frozenset(),
    revinfo: bool = True,
) -> "Signed":
    card, leaf = make_card(pki, "FIRMANTE " + level.value)
    stamper, tsa_cert = make_timestamper(pki, fail_on)
    context = signing_validation_context(
        pki.store,
        online=False,
        ocsp_responses=[pki.ocsp(leaf), pki.ocsp(tsa_cert)] if revinfo else [],
        crls=[pki.arl()] if revinfo else [],
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_pdf_pades(
            minimal_pdf(),
            token,
            (pki.root, pki.ca, leaf),
            level=level,
            timestamper=stamper,
            validation_context=context,
        )
    return Signed(result, leaf, tsa_cert, stamper, card.instructions().count(INS_PSO))


def test_b_t_carries_a_signature_timestamp(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_T)
    result = signed.result
    assert result.level is SignatureLevel.B_T
    assert result.note is None
    assert signed.card_signatures == 1
    # B-T carries no validation data: the verifier gets it online; supplied here.
    revinfo = [pki.ocsp(signed.leaf), pki.ocsp(signed.tsa)]
    verification = verify_pdf(
        result.data, pki.store, online=False, ocsp_responses=revinfo, crls=[pki.arl()]
    )
    [report] = verification.signatures
    assert report.indication is Indication.TOTAL_PASSED
    assert report.timestamp is not None
    assert report.timestamp.indication is Indication.TOTAL_PASSED


def test_b_lt_embeds_the_validation_data(pki: Pki) -> None:
    """Verifiable without network: everything needed is in the document."""
    result = _sign(pki, SignatureLevel.B_LT).result
    assert result.level is SignatureLevel.B_LT
    verification = verify_pdf(result.data, pki.store, online=False)
    [report] = verification.signatures
    assert report.indication is Indication.TOTAL_PASSED
    assert report.document_unchanged_since_signing
    assert verification.document_timestamps == ()


def test_b_lta_adds_a_document_timestamp(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_LTA)
    result = signed.result
    assert result.level is SignatureLevel.B_LTA
    verification = verify_pdf(
        result.data, pki.store, online=False, ocsp_responses=[pki.ocsp(signed.tsa)]
    )
    assert verification.signatures[0].indication is Indication.TOTAL_PASSED
    [stamp] = verification.document_timestamps
    assert stamp.field_name == "SelloBerigna1"
    assert stamp.indication is Indication.TOTAL_PASSED


def test_missing_validation_data_keeps_the_b_t_signature(pki: Pki) -> None:
    """The card already signed: the work is kept, with the level reached and the reason."""
    result = _sign(pki, SignatureLevel.B_LT, revinfo=False).result
    assert result.level is SignatureLevel.B_T
    assert result.note is not None
    assert result.note.startswith("validation data not embedded")


def test_failed_document_timestamp_keeps_the_b_lt_signature(pki: Pki) -> None:
    signed = _sign(pki, SignatureLevel.B_LTA, fail_on=frozenset({3}))
    result = signed.result
    assert signed.stamper.calls == 3
    assert result.level is SignatureLevel.B_LT
    assert result.note is not None
    assert result.note.startswith("document time-stamp not added")


def test_tsa_failure_on_the_signature_timestamp_gives_nothing(pki: Pki) -> None:
    with pytest.raises(TsaError):
        _sign(pki, SignatureLevel.B_T, fail_on=frozenset({2}))


@pytest.mark.parametrize(
    ("level", "missing"),
    [(SignatureLevel.B_T, "timestamper"), (SignatureLevel.B_LT, "validation_context")],
)
def test_levels_require_their_services(pki: Pki, level: SignatureLevel, missing: str) -> None:
    card, leaf = make_card(pki, "FIRMANTE")
    stamper, _ = make_timestamper(pki)
    kwargs = {"timestamper": stamper, "validation_context": None}
    kwargs[missing] = None
    with DnieV2Token(card) as token, pytest.raises(ValueError, match="needs"):
        sign_pdf_pades(minimal_pdf(), token, (pki.root, pki.ca, leaf), level=level, **kwargs)  # type: ignore[arg-type]
    assert INS_PSO not in card.instructions()


def test_a_tsa_whose_path_cannot_be_built_keeps_the_b_t(pki: Pki) -> None:
    """Same regression as in CAdES: PathBuildingError is a service failure after signing."""
    card, leaf = make_card(pki, "FIRMANTE")
    stamper = unknown_timestamper()  # its path cannot be built: PathBuildingError
    context = signing_validation_context(
        pki.store, online=False, ocsp_responses=[pki.ocsp(leaf)], crls=[pki.arl()]
    )
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_pdf_pades(
            minimal_pdf(),
            token,
            (pki.root, pki.ca, leaf),
            level=SignatureLevel.B_LT,
            timestamper=stamper,
            validation_context=context,
        )
    assert result.level is SignatureLevel.B_T
    assert result.note is not None
    assert card.instructions().count(INS_PSO) == 1
