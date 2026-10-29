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
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from pyhanko.sign.timestamps import TimeStamper

from berigna.core.appearance import VisibleSignature, render_appearance, stamp_data
from berigna.core.errors import (
    AppearanceError,
    LevelNotAvailableError,
    OutputExistsError,
    SigningCancelledError,
    SourceChangedError,
)
from berigna.core.files import write_atomically
from berigna.core.formats.pades import (
    PadesOptions,
    SignatureLevel,
    VisibleStamp,
    check_pdf_signable,
    page_count,
    page_geometry,
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


def output_path(source: Path, suffix: str, directory: Path | None = None) -> Path:
    """Where to write the signed copy of ``source``: ``<name><suffix>.pdf`` in ``directory``
    (the folder of ``source`` by default), numbered when that name is taken (RF-045)."""
    folder = directory or source.parent
    candidate = folder / f"{source.stem}{suffix}{source.suffix}"
    number = 2
    while candidate.exists():
        candidate = folder / f"{source.stem}{suffix}-{number}{source.suffix}"
        number += 1
    return candidate


def _visible_stamp(
    visible: VisibleSignature,
    check: SignerCheck,
    options: PadesOptions,
    source: Path,
    expected_sha256: str,
) -> VisibleStamp:
    pdf = _read_unchanged(source, expected_sha256)
    pages = page_count(pdf)
    if not 0 <= visible.page < pages:
        raise AppearanceError(f"page {visible.page + 1} of {pages} does not exist")
    geometry = page_geometry(pdf, visible.page)
    if geometry.rotation:
        raise AppearanceError(f"page {visible.page + 1} is rotated {geometry.rotation} degrees")
    data = stamp_data(
        check.chain[-1], dni=visible.dni, reason=options.reason, location=options.location
    )
    # The box is relative to what the preview shows, the crop box; the field is placed in
    # the coordinates of the page.
    x, y, width, height = visible.box
    x, y = x + geometry.x, y + geometry.y
    box = (round(x), round(y), round(x + width), round(y + height))
    return VisibleStamp(visible.page, box, render_appearance(visible, data))


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
    visible: VisibleSignature | None = None,
) -> SignResult:
    """Sign ``source`` in PAdES at ``level`` and write it to ``output``. See the module docstring.

    With ``visible``, the appearance is drawn with the signer's data before the PIN is
    requested, so a box on a missing page or an unreadable image costs no PIN entry.

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
    opts = options or PadesOptions()
    if visible is not None:
        opts = replace(opts, visible=_visible_stamp(visible, check, opts, source, expected_sha256))
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
        opts,
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
