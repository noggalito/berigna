# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Signing orchestration (flujos-de-firma-y-verificacion §1), independent of the UI.

Order of the steps is part of the security design:

1. The file must still be the one the user saw (SHA-256 of the previewed bytes, RF-018),
   and it must be a PDF that can be signed.
2. The signer certificate is validated before any PIN is requested (RF-006). A level above
   B-B needs revocation to have been checked, and a TSA that has just issued a time-stamp
   (probe): both are known before the PIN, so neither failure costs a PIN entry.
3. The PIN is requested through a callback (the UI), which may cancel (P-01).
4. The file is checked again right before signing, and the bytes in memory are signed.
5. The output is written atomically and never over an existing file (RF-045).
"""

import hashlib
import os
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from pyhanko.sign.timestamps import TimeStamper

from berigna.core.errors import (
    LevelNotAvailableError,
    OutputExistsError,
    SigningCancelledError,
    SourceChangedError,
)
from berigna.core.formats.pades import (
    PadesOptions,
    SignatureLevel,
    check_pdf_signable,
    sign_pdf_pades,
)
from berigna.core.net.tsa import probe
from berigna.core.token.base import TokenSigner
from berigna.core.token.pin import Pin
from berigna.core.trust import TrustStore
from berigna.core.validation import SignerCheck, check_signer, signing_validation_context

AskPin = Callable[[SignerCheck], Pin | None]


@dataclass(frozen=True)
class SignResult:
    output: Path
    sha256: str
    level: SignatureLevel  # reached; lower than requested only when level_note says why
    revocation_checked: bool
    level_note: str | None = None


def _read_unchanged(path: Path, expected_sha256: str) -> bytes:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise SourceChangedError(f"{path.name} changed after it was shown")
    return data


def write_atomically(path: Path, data: bytes, *, replace: bool = False) -> None:
    """Write ``data`` to ``path`` with fsync, all or nothing (RNF-FIA-01).

    Never replaces an existing file unless ``replace`` is given, which is for files the user
    chose to overwrite in a save dialog (reports), never for signed documents.
    """
    if not replace and path.exists():
        raise OutputExistsError(f"{path.name} already exists")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
            return
        os.link(temporary, path)  # fails if path appeared meanwhile: no silent overwrite
    except FileExistsError as exc:
        raise OutputExistsError(f"{path.name} already exists") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sign_pdf_file(
    source: Path,
    output: Path,
    *,
    expected_sha256: str,
    token: TokenSigner,
    store: TrustStore,
    ask_pin: AskPin,
    options: PadesOptions | None = None,
    level: SignatureLevel = SignatureLevel.B_B,
    timestamper: TimeStamper | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> SignResult:
    """Sign ``source`` in PAdES at ``level`` and write it to ``output``. See the module docstring.

    Raises :class:`~berigna.core.errors.LevelNotAvailableError` (before the PIN) when the level
    needs a TSA and none is given, or revocation could not be checked (RF-006: B-B only).
    """
    check_pdf_signable(_read_unchanged(source, expected_sha256))
    if output.exists():
        raise OutputExistsError(f"{output.name} already exists")
    stamper = timestamper if level is not SignatureLevel.B_B else None
    if level is not SignatureLevel.B_B and stamper is None:
        raise LevelNotAvailableError(f"{level.value} needs a TSA")

    check = check_signer(
        token.signing_certificate(),
        store,
        online=online,
        ocsp_responses=ocsp_responses,
        crls=crls,
    )
    if stamper is not None:
        if check.only_basic_level:
            raise LevelNotAvailableError(f"revocation not checked: B-B only, not {level.value}")
        probe(stamper)
    pin = ask_pin(check)
    if pin is None:
        raise SigningCancelledError("signature cancelled before sending the PIN")
    token.verify_pin(pin)

    data = _read_unchanged(source, expected_sha256)
    context = (
        signing_validation_context(store, online=online, ocsp_responses=ocsp_responses, crls=crls)
        if level in (SignatureLevel.B_LT, SignatureLevel.B_LTA)
        else None
    )
    result = sign_pdf_pades(
        data,
        token,
        check.chain,
        options,
        level=level,
        timestamper=stamper,
        validation_context=context,
    )
    write_atomically(output, result.data)
    return SignResult(
        output=output,
        sha256=hashlib.sha256(result.data).hexdigest(),
        level=result.level,
        revocation_checked=check.revocation_checked,
        level_note=result.note,
    )
