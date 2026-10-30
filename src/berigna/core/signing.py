# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing orchestration (flujos-de-firma-y-verificacion §1), independent of the UI.

Order of the steps is part of the security design:

1. The file must still be the one the user saw (SHA-256 of the previewed bytes, RF-018),
   and, for PAdES, a PDF that can be signed.
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
from typing import Protocol

from pyhanko.sign.timestamps import TimeStamper
from pyhanko_certvalidator import ValidationContext

from berigna.core.appearance import VisibleSignature, render_appearance, stamp_data
from berigna.core.errors import (
    AppearanceError,
    LevelNotAvailableError,
    OutputExistsError,
    SigningCancelledError,
    SourceChangedError,
)
from berigna.core.files import write_atomically
from berigna.core.formats.cades import CadesPackaging, sign_cades
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
from berigna.core.token.base import HashAlgorithmName, TokenSigner
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


def _free_name(folder: Path, name: Callable[[str], str]) -> Path:
    """The first ``name("")``, ``name("-2")``, ``name("-3")``… not taken in ``folder`` (RF-045)."""
    candidate = folder / name("")
    number = 2
    while candidate.exists():
        candidate = folder / name(f"-{number}")
        number += 1
    return candidate


def output_path(source: Path, suffix: str, directory: Path | None = None) -> Path:
    """Where to write the signed copy of ``source``: ``<name><suffix>.pdf`` in ``directory``
    (the folder of ``source`` by default), numbered when that name is taken (RF-045)."""
    return _free_name(
        directory or source.parent, lambda n: f"{source.stem}{suffix}{n}{source.suffix}"
    )


def cades_output_path(
    source: Path, packaging: CadesPackaging, directory: Path | None = None
) -> Path:
    """Where to write the CAdES signature of ``source``: ``<name>.p7s`` or ``<name>.p7m``
    (RF-020, RF-021) in ``directory`` (the folder of ``source`` by default). When that name is
    taken, the number goes before the extension of the file, ``acta-2.xml.p7m``, so that
    removing ``.p7m`` or ``.p7s`` still gives a name of the right type (RF-045)."""
    return _free_name(
        directory or source.parent,
        lambda n: f"{source.stem}{n}{source.suffix}.{packaging.value}",
    )


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
    check_pdf_signable(check_source(source, output, expected_sha256))
    stamper, check = prepare(
        token, store, level, timestamper, online=online, ocsp_responses=ocsp_responses, crls=crls
    )
    opts = options or PadesOptions()
    if visible is not None:
        opts = replace(opts, visible=_visible_stamp(visible, check, opts, source, expected_sha256))
    send_pin(token, ask_pin, check)
    return sign_checked(
        SigningJob(source, output, expected_sha256),
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


# -- Steps, shared with batch signing (berigna.core.batch) ----------------------------------------


@dataclass(frozen=True)
class SigningJob:
    """One file to sign: the bytes shown to the user (by their SHA-256) go to ``output``."""

    source: Path
    output: Path
    expected_sha256: str


def check_source(source: Path, output: Path, expected_sha256: str) -> bytes:
    """Step 1: still the file the user saw, and a free output; returns the bytes, which the
    PDF callers also check with :func:`~berigna.core.formats.pades.check_pdf_signable`."""
    data = _read_unchanged(source, expected_sha256)
    if output.exists():
        raise OutputExistsError(f"{output.name} already exists")
    return data


def time_stamper(level: SignatureLevel, timestamper: TimeStamper | None) -> TimeStamper | None:
    stamper = timestamper if level is not SignatureLevel.B_B else None
    if level is not SignatureLevel.B_B and stamper is None:
        raise LevelNotAvailableError(f"{level.value} needs a TSA")
    return stamper


def check_level(check: SignerCheck, level: SignatureLevel, stamper: TimeStamper | None) -> None:
    """Step 2: a level above B-B needs revocation checked and a TSA that answers."""
    if stamper is not None:
        if check.only_basic_level:
            raise LevelNotAvailableError(f"revocation not checked: B-B only, not {level.value}")
        probe(stamper)


def prepare(
    token: TokenSigner,
    store: TrustStore,
    level: SignatureLevel,
    timestamper: TimeStamper | None,
    *,
    online: bool,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> tuple[TimeStamper | None, SignerCheck]:
    """Step 2, whatever the format: the TSA a level needs, the signer certificate validated
    and the level checked against both, all before the PIN (RF-006)."""
    stamper = time_stamper(level, timestamper)
    check = check_signer(
        token.signing_certificate(),
        store,
        online=online,
        ocsp_responses=ocsp_responses,
        crls=crls,
    )
    check_level(check, level, stamper)
    return stamper, check


def send_pin(token: TokenSigner, ask_pin: AskPin, check: SignerCheck) -> None:
    """Step 3: the PIN, through the UI, which may cancel; sent once (P-06)."""
    pin = ask_pin(check)
    if pin is None:
        raise SigningCancelledError("signature cancelled before sending the PIN")
    token.verify_pin(pin)


def sign_checked(
    job: SigningJob,
    *,
    token: TokenSigner,
    store: TrustStore,
    check: SignerCheck,
    options: PadesOptions,
    level: SignatureLevel,
    timestamper: TimeStamper | None,
    online: bool,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> SignResult:
    """Steps 4 and 5, with the PIN already verified: sign the unchanged bytes and write them."""
    return _sign_and_write(
        job,
        store=store,
        check=check,
        level=level,
        online=online,
        ocsp_responses=ocsp_responses,
        crls=crls,
        sign=lambda data, context: sign_pdf_pades(
            data,
            token,
            check.chain,
            options,
            level=level,
            timestamper=timestamper,
            validation_context=context,
        ),
    )


class _Signed(Protocol):
    """What :func:`sign_pdf_pades` and :func:`sign_cades` return (frozen dataclasses)."""

    @property
    def data(self) -> bytes: ...
    @property
    def level(self) -> SignatureLevel: ...
    @property
    def note(self) -> str | None: ...


def _sign_and_write(
    job: SigningJob,
    *,
    store: TrustStore,
    check: SignerCheck,
    level: SignatureLevel,
    online: bool,
    ocsp_responses: Sequence[bytes],
    crls: Sequence[bytes],
    sign: Callable[[bytes, ValidationContext | None], _Signed],
) -> SignResult:
    """Steps 4 and 5, whatever the format: re-read the unchanged bytes, sign them with the
    validation context a long-term level needs, and write the result atomically."""
    data = _read_unchanged(job.source, job.expected_sha256)
    context = (
        signing_validation_context(store, online=online, ocsp_responses=ocsp_responses, crls=crls)
        if level in (SignatureLevel.B_LT, SignatureLevel.B_LTA)
        else None
    )
    result = sign(data, context)
    write_atomically(job.output, result.data)
    return SignResult(
        output=job.output,
        sha256=hashlib.sha256(result.data).hexdigest(),
        level=result.level,
        revocation_checked=check.revocation_checked,
        level_note=result.note,
    )


# -- CAdES of any file (RF-020 to RF-022) ---------------------------------------------------------


def sign_cades_file(
    source: Path,
    output: Path,
    *,
    expected_sha256: str,
    token: TokenSigner,
    store: TrustStore,
    ask_pin: AskPin,
    packaging: CadesPackaging = CadesPackaging.DETACHED,
    level: SignatureLevel = SignatureLevel.B_B,
    digest: HashAlgorithmName = "sha256",
    timestamper: TimeStamper | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> SignResult:
    """Sign ``source`` in CAdES at ``level`` and write the signature to ``output``, in the same
    order of steps as :func:`sign_pdf_file` (module docstring). The source is never changed:
    a ``.p7s`` holds only the signature, a ``.p7m`` the signature and a copy of the file."""
    check_source(source, output, expected_sha256)
    stamper, check = prepare(
        token, store, level, timestamper, online=online, ocsp_responses=ocsp_responses, crls=crls
    )
    send_pin(token, ask_pin, check)
    return sign_cades_checked(
        SigningJob(source, output, expected_sha256),
        token=token,
        store=store,
        check=check,
        packaging=packaging,
        level=level,
        digest=digest,
        timestamper=stamper,
        online=online,
        ocsp_responses=ocsp_responses,
        crls=crls,
    )


def sign_cades_checked(
    job: SigningJob,
    *,
    token: TokenSigner,
    store: TrustStore,
    check: SignerCheck,
    packaging: CadesPackaging,
    level: SignatureLevel,
    digest: HashAlgorithmName,
    timestamper: TimeStamper | None,
    online: bool,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
) -> SignResult:
    """Steps 4 and 5 for CAdES, with the PIN already verified (batch signing reuses it)."""
    return _sign_and_write(
        job,
        store=store,
        check=check,
        level=level,
        online=online,
        ocsp_responses=ocsp_responses,
        crls=crls,
        sign=lambda data, context: sign_cades(
            data,
            token,
            check.chain,
            packaging=packaging,
            level=level,
            digest=digest,
            timestamper=timestamper,
            validation_context=context,
        ),
    )
