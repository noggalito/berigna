# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Signing orchestration (flujos-de-firma-y-verificacion §1), independent of the UI.

Order of the steps is part of the security design:

1. The file must still be the one the user saw (SHA-256 of the previewed bytes, RF-018).
2. The signer certificate is validated before any PIN is requested (RF-006).
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

from berigna.core.errors import OutputExistsError, SigningCancelledError, SourceChangedError
from berigna.core.formats.pades import PadesOptions, sign_pdf_basic
from berigna.core.token.base import TokenSigner
from berigna.core.token.pin import Pin
from berigna.core.trust import TrustStore
from berigna.core.validation import SignerCheck, check_signer

AskPin = Callable[[SignerCheck], Pin | None]


@dataclass(frozen=True)
class SignResult:
    output: Path
    sha256: str
    level: str
    revocation_checked: bool


def _read_unchanged(path: Path, expected_sha256: str) -> bytes:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise SourceChangedError(f"{path.name} changed after it was shown")
    return data


def write_atomically(path: Path, data: bytes) -> None:
    """Write ``data`` to a new file ``path`` (never replacing one) with fsync (RNF-FIA-01)."""
    if path.exists():
        raise OutputExistsError(f"{path.name} already exists")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)  # fails if path appeared meanwhile: no silent overwrite
    except FileExistsError as exc:
        raise OutputExistsError(f"{path.name} already exists") from exc
    finally:
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
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> SignResult:
    """Sign ``source`` in PAdES B-B and write it to ``output``. See the module docstring."""
    _read_unchanged(source, expected_sha256)
    if output.exists():
        raise OutputExistsError(f"{output.name} already exists")

    check = check_signer(
        token.signing_certificate(),
        store,
        online=online,
        ocsp_responses=ocsp_responses,
        crls=crls,
    )
    pin = ask_pin(check)
    if pin is None:
        raise SigningCancelledError("signature cancelled before sending the PIN")
    token.verify_pin(pin)

    data = _read_unchanged(source, expected_sha256)
    signed = sign_pdf_basic(data, token, check.chain, options)
    write_atomically(output, signed)
    return SignResult(
        output=output,
        sha256=hashlib.sha256(signed).hexdigest(),
        level="B-B",
        revocation_checked=check.revocation_checked,
    )
