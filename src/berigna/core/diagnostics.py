# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Diagnosis of the reader, the DNIe and the services (CU-07, RF-007).

The checks run in order, as the user would: the smart card service, the reader, the card,
its signing certificate (read without the PIN), the certificate's validity and revocation
online, and the time-stamping authority. A step that cannot run because an earlier one failed
is reported as skipped. Each result carries a key, that the interface turns into words and a
suggested action, and the few facts it needs; the report never holds the PIN, and the DNI only
as its last four digits.
"""

import datetime as dt
import enum
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from pyhanko.sign.timestamps import TimeStamper

from berigna.core.errors import BerignaError
from berigna.core.net.tsa import probe
from berigna.core.report.explanations import common_name, masked_id
from berigna.core.token.base import TokenSigner
from berigna.core.token.monitor import DeviceState, DeviceStatus
from berigna.core.trust import TrustStore
from berigna.core.validation import check_signer
from berigna.core.validation.preflight import EXPIRY_WARNING

log = logging.getLogger(__name__)


class Status(enum.Enum):
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


class Step(enum.Enum):
    PCSC = "pcsc"
    READER = "reader"
    CARD = "card"
    CERTIFICATE = "certificate"
    VALIDATION = "validation"
    TSA = "tsa"


@dataclass(frozen=True)
class Result:
    step: Step
    status: Status
    code: str | None = None  # ERR-xxx when the step failed with one
    facts: dict[str, str] = field(default_factory=dict)  # shown with the result


def diagnose(
    status: DeviceStatus | None,
    *,
    open_token: Callable[[], TokenSigner],
    store: TrustStore,
    timestamper: TimeStamper | None,
    online: bool = True,
    moment: dt.datetime | None = None,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> list[Result]:
    """One :class:`Result` per :class:`Step`, in order. Never asks for the PIN.

    ``moment`` is for the tests: without it, the certificate is validated "now", which allows
    RENIEC's OCSP answers a few minutes of clock difference (CURRENT_TIME_TOLERANCE); a fixed
    moment allows one second, and a real answer then looked "too recent" (2026-10-29)."""
    validate_at = moment
    moment = moment or dt.datetime.now(dt.UTC)
    state = status.state if status is not None else DeviceState.PCSC_UNAVAILABLE
    results = [
        Result(Step.PCSC, Status.ERROR if state is DeviceState.PCSC_UNAVAILABLE else Status.OK)
    ]
    readers = ", ".join(status.readers) if status is not None else ""
    if state is DeviceState.PCSC_UNAVAILABLE:
        results.append(Result(Step.READER, Status.SKIPPED))
    elif state is DeviceState.NO_READER:
        results.append(Result(Step.READER, Status.ERROR))
    else:
        results.append(Result(Step.READER, Status.OK, facts={"readers": readers}))

    if status is not None and state is DeviceState.DNIE_READY:
        results.append(Result(Step.CARD, Status.OK, facts={"reader": status.reader or ""}))
    elif state in (DeviceState.NO_CARD, DeviceState.UNSUPPORTED_CARD):
        atr = status.atr.hex(" ").upper() if status and status.atr else ""
        facts = {"atr": atr} if atr else {}
        results.append(Result(Step.CARD, Status.ERROR, facts=facts))
    else:
        results.append(Result(Step.CARD, Status.SKIPPED))

    if results[-1].status is Status.OK:
        results += _certificate(
            open_token, store, online, moment, validate_at, ocsp_responses, crls
        )
    else:
        results += [
            Result(Step.CERTIFICATE, Status.SKIPPED),
            Result(Step.VALIDATION, Status.SKIPPED),
        ]
    results.append(_tsa(timestamper, online))
    for result in results:
        if result.status is not Status.OK:
            log.info(
                "diagnosis %s: %s %s %s",
                result.step.value,
                result.status.value,
                result.code or "",
                result.facts,
            )
    return results


def _certificate(
    open_token: Callable[[], TokenSigner],
    store: TrustStore,
    online: bool,
    moment: dt.datetime,
    validate_at: dt.datetime | None,
    ocsp_responses: Sequence[bytes],
    crls: Sequence[bytes],
) -> list[Result]:
    try:
        with open_token() as token:
            certificate = token.signing_certificate()
    except BerignaError as exc:
        return [
            Result(Step.CERTIFICATE, Status.ERROR, exc.code),
            Result(Step.VALIDATION, Status.SKIPPED),
        ]
    expires = certificate.not_valid_after_utc
    facts = {
        "signer": common_name(certificate),
        "dni": masked_id(certificate) or "",
        "expires": expires.isoformat(),
        "days": str(max(0, (expires - moment).days)),
    }
    if expires <= moment:
        cert_status = Status.ERROR
    elif expires - moment < EXPIRY_WARNING:
        cert_status = Status.WARNING
    else:
        cert_status = Status.OK
    results = [
        Result(Step.CERTIFICATE, cert_status, "ERR-211" if expires <= moment else None, facts)
    ]
    try:
        check = check_signer(
            certificate,
            store,
            moment=validate_at,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
        )
    except BerignaError as exc:
        results.append(Result(Step.VALIDATION, Status.ERROR, exc.code))
    else:
        if check.revocation_checked:
            results.append(Result(Step.VALIDATION, Status.OK))
        else:
            note = check.revocation_note.value if check.revocation_note else ""
            results.append(Result(Step.VALIDATION, Status.WARNING, facts={"note": note}))
    return results


def _tsa(timestamper: TimeStamper | None, online: bool) -> Result:
    if timestamper is None or not online:
        return Result(Step.TSA, Status.SKIPPED, facts={"configured": str(timestamper is not None)})
    try:
        probe(timestamper)
    except BerignaError as exc:
        return Result(Step.TSA, Status.ERROR, exc.code)
    return Result(Step.TSA, Status.OK)
