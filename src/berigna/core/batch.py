# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing several files with one PIN (CU-04; RF-040 to RF-043).

Each file is signed in the format of its job (RF-041): PAdES, or CAdES or XAdES in a
packaging. The same order as :func:`berigna.core.signing.sign_pdf_file`, once for the whole
batch:

1. Every file is checked (unchanged since the user confirmed the list, a PDF or an XML that
   can be signed in its format, a free output). Those that fail are reported and left out,
   before the PIN.
2. The signer certificate and the level are checked once (RF-006).
3. The PIN is asked once and sent once: on the DNIe v2 one VERIFY covers the whole session
   (SPK-01 §8.6).
4. Each file is signed in turn. An error in one file does not stop the others (RF-043),
   even one berigna does not know (ERR-000), and the user can cancel between files. A card
   removed or a session that no longer accepts operations stops the batch: the files left
   are reported as not signed.

Closing the token session (power off the card) is the caller's ``with`` block.
"""

import enum
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from pyhanko.sign.timestamps import TimeStamper

from berigna.core.errors import BatchCancelledError, BerignaError, TokenError
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.pades import PadesOptions, SignatureLevel, check_pdf_signable
from berigna.core.formats.xades import XadesPackaging, check_xml_signable
from berigna.core.signing import (
    AskPin,
    Packaging,
    SigningJob,
    SignResult,
    check_source,
    prepare,
    send_pin,
    sign_cades_checked,
    sign_checked,
    sign_xades_checked,
    signed_output_path,
)
from berigna.core.token.base import TokenSigner
from berigna.core.trust import TrustStore
from berigna.core.validation import SignerCheck


class Outcome(enum.Enum):
    SIGNED = "signed"
    FAILED = "failed"  # this file could not be signed; the others went on
    SKIPPED = "skipped"  # not attempted: cancelled, or the batch stopped before it


@dataclass(frozen=True)
class BatchItem:
    job: SigningJob
    outcome: Outcome
    result: SignResult | None = None
    code: str | None = None  # ERR-xxx of a failed or skipped file
    detail: str | None = None  # for the technical log, never shown as is


Progress = Callable[[int, int, BatchItem], None]  # done, total, last item


def batch_outputs(
    sources: Sequence[Path],
    suffix: str,
    directory: Path | None = None,
    packagings: Sequence[Packaging] | None = None,
) -> list[Path]:
    """Output of each source, in its packaging (PAdES by default), named as
    :func:`~berigna.core.signing.signed_output_path` does, and never the same for two of them:
    two "contrato.pdf" from different folders into one output folder get "contrato-firmado.pdf"
    and "contrato-firmado-2.pdf" (RF-045)."""
    taken: set[Path] = set()
    outputs = []
    for index, source in enumerate(sources):
        packaging = packagings[index] if packagings is not None else None
        output = signed_output_path(source, packaging, suffix, directory, taken)
        taken.add(output)
        outputs.append(output)
    return outputs


def check_job(job: SigningJob) -> None:
    """Step 1 for one file of the batch, in its format: unchanged, signable, free output."""
    data = check_source(job.source, job.output, job.expected_sha256)
    if job.packaging is None:
        check_pdf_signable(data)
    elif isinstance(job.packaging, XadesPackaging):
        check_xml_signable(data, job.packaging)


def _failed(job: SigningJob, error: BerignaError, outcome: Outcome = Outcome.FAILED) -> BatchItem:
    return BatchItem(job, outcome, code=error.code, detail=str(error))


def sign_batch(
    jobs: Sequence[SigningJob],
    *,
    token: TokenSigner,
    store: TrustStore,
    ask_pin: AskPin,
    options: PadesOptions | None = None,
    level: SignatureLevel = SignatureLevel.B_B,
    timestamper: TimeStamper | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    cancelled: Callable[[], bool] = lambda: False,
    progress: Progress | None = None,
) -> list[BatchItem]:
    """Sign ``jobs`` with one PIN, each in its format; one :class:`BatchItem` per job, in
    order. ``options`` are those of PAdES; CAdES and XAdES take only its digest algorithm.

    Errors common to the whole batch (certificate, level, TSA, PIN, cancellation before the
    PIN) are raised, as in :func:`~berigna.core.signing.sign_pdf_file`, and nothing is signed.
    """
    items: dict[int, BatchItem] = {}
    pending: list[int] = []
    for index, job in enumerate(jobs):
        try:
            check_job(job)
        except BerignaError as exc:
            items[index] = _failed(job, exc)
        else:
            pending.append(index)

    if pending:
        stamper, check = prepare(
            token,
            store,
            level,
            timestamper,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
        )
        send_pin(token, ask_pin, check)
        opts = options or PadesOptions()
        stopped: BerignaError | None = None
        for index in pending:
            job = jobs[index]
            if stopped is not None:
                items[index] = _failed(job, stopped, Outcome.SKIPPED)
                continue
            if cancelled():
                stopped = BatchCancelledError("batch cancelled by the user")
                items[index] = _failed(job, stopped, Outcome.SKIPPED)
                continue
            try:
                result = _sign_job(
                    job,
                    token=token,
                    store=store,
                    check=check,
                    options=opts,
                    level=level,
                    timestamper=stamper,
                    online=online,
                    ocsp_responses=ocsp_responses,
                    crls=crls,
                )
            except TokenError as exc:
                # The card is gone or no longer authenticated: nothing else can be signed.
                items[index] = _failed(job, exc)
                stopped = exc
            except BerignaError as exc:
                items[index] = _failed(job, exc)
            except Exception as exc:  # one file must not stop the batch (RF-043)
                unexpected = BerignaError(f"unexpected error: {type(exc).__name__}: {exc}")
                items[index] = _failed(job, unexpected)
            else:
                items[index] = BatchItem(job, Outcome.SIGNED, result)
            if progress is not None:
                progress(len(items), len(jobs), items[index])
    return [items[index] for index in range(len(jobs))]


def _sign_job(
    job: SigningJob,
    *,
    token: TokenSigner,
    store: TrustStore,
    check: SignerCheck,
    options: PadesOptions,
    level: SignatureLevel,
    timestamper: TimeStamper | None,
    online: bool,
    ocsp_responses: Sequence[bytes],
    crls: Sequence[bytes],
) -> SignResult:
    """Steps 4 and 5 for one file, in the format of its job."""
    if isinstance(job.packaging, CadesPackaging):
        return sign_cades_checked(
            job,
            token=token,
            store=store,
            check=check,
            packaging=job.packaging,
            level=level,
            digest=options.digest,
            timestamper=timestamper,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
        )
    if isinstance(job.packaging, XadesPackaging):
        return sign_xades_checked(
            job,
            token=token,
            store=store,
            check=check,
            packaging=job.packaging,
            level=level,
            digest=options.digest,
            timestamper=timestamper,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
        )
    return sign_checked(
        job,
        token=token,
        store=store,
        check=check,
        options=options,
        level=level,
        timestamper=timestamper,
        online=online,
        ocsp_responses=ocsp_responses,
        crls=crls,
    )
