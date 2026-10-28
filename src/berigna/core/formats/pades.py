# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""PAdES signatures with pyHanko 0.25.x; the private-key operation happens in the token.

Baseline levels (ETSI EN 319 142-1):

- B-B: the signature alone.
- B-T: plus a signature time-stamp from a TSA (RF-062).
- B-LT: plus the validation data (certificates, OCSP responses, CRLs of the CAs) in the DSS,
  gathered with the signing rules of :func:`berigna.core.validation.signing_validation_context`.
- B-LTA: plus a document time-stamp over all of it.

The levels above B-T are added after the card has signed, as incremental updates. If one of
them fails (a service does not answer), the signature already made is not thrown away: the
result carries the level actually reached and the reason, and the caller must tell the user.
"""

import asyncio
import enum
import hashlib
import io
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asn1crypto import algos
from cryptography import x509
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.fields import MDPPerm, SigFieldSpec, SigSeedSubFilter, enumerate_sig_fields
from pyhanko.sign.general import SigningError
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.sign.timestamps.common_utils import TimestampRequestError
from pyhanko.sign.validation import read_certification_data
from pyhanko.sign.validation.dss import async_add_validation_info
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.stamp import StaticStampStyle
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.errors import CRLValidationError, OCSPValidationError, ValidationError
from pyhanko_certvalidator.registry import SimpleCertificateStore

from berigna.core.certs import to_asn1
from berigna.core.errors import CertifiedDocumentError, PdfFormatError, TsaError
from berigna.core.token.base import HashAlgorithmName, TokenSigner

_SIGNATURE_SIZE = 256  # RSA-2048 (DNIe v2, SPK-01)
_FIELD_PREFIX = "FirmaBerigna"
_TIMESTAMP_PREFIX = "SelloBerigna"

# Failures of a service after the card has signed: they lower the level, they do not lose work.
_SERVICE_ERRORS = (
    TimestampRequestError,
    ValidationError,
    CRLValidationError,
    OCSPValidationError,
    SignatureValidationError,
    PdfError,
    ValueError,
)


class SignatureLevel(enum.Enum):
    B_B = "B-B"
    B_T = "B-T"
    B_LT = "B-LT"
    B_LTA = "B-LTA"


@dataclass(frozen=True)
class PadesResult:
    data: bytes
    level: SignatureLevel  # level reached; lower than requested only if ``note`` says why
    note: str | None = None


@dataclass(frozen=True)
class VisibleStamp:
    """A visible signature field: page (from 0), box (x1, y1, x2, y2) in PDF points and its
    appearance as a one-page PDF (:func:`berigna.core.appearance.render_appearance`)."""

    page: int
    box: tuple[int, int, int, int]
    appearance: bytes


@dataclass(frozen=True)
class PadesOptions:
    """Optional signature dictionary entries (RF-013) and the visible signature (RF-012)."""

    reason: str | None = None
    location: str | None = None
    contact: str | None = None
    digest: HashAlgorithmName = "sha256"
    visible: VisibleStamp | None = None


def _registry(certificates: Sequence[x509.Certificate]) -> SimpleCertificateStore:
    store = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    for certificate in certificates:
        store.register(to_asn1(certificate))
    return store


class _TokenPdfSigner(signers.Signer):
    """pyHanko signer that hashes locally and lets the token sign the digest (RNF-SEG-01)."""

    def __init__(
        self,
        token: TokenSigner,
        chain: Sequence[x509.Certificate],
        digest: HashAlgorithmName,
    ) -> None:
        super().__init__(
            signing_cert=to_asn1(chain[-1]),
            cert_registry=_registry(chain[:-1]),
            signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": f"{digest}_rsa"}),
            embed_roots=False,
        )
        self._token = token
        self._digest: HashAlgorithmName = digest

    async def async_sign_raw(
        self, data: bytes, digest_algorithm: str, dry_run: bool = False
    ) -> bytes:
        if dry_run:
            return bytes(_SIGNATURE_SIZE)
        if digest_algorithm != self._digest:
            raise ValueError(f"unexpected digest algorithm {digest_algorithm!r}")
        return self._token.sign_digest(hashlib.new(digest_algorithm, data).digest(), self._digest)


def _open(pdf: bytes) -> tuple[IncrementalPdfFileWriter, set[str]]:
    try:
        writer = IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
        existing = {name for name, _, _ in enumerate_sig_fields(writer)}
    except (PdfError, KeyError, ValueError) as exc:
        raise PdfFormatError(f"cannot read this PDF: {exc}") from exc
    return writer, existing


def page_count(pdf: bytes) -> int:
    return int(_open(pdf)[0].prev.root["/Pages"]["/Count"])


@dataclass(frozen=True)
class PageGeometry:
    """What a preview shows of a page: its crop box (origin and size) and its rotation."""

    x: float
    y: float
    width: float
    height: float
    rotation: int  # degrees, 0, 90, 180 or 270


def page_geometry(pdf: bytes, index: int) -> PageGeometry:
    """Crop box (or media box) and rotation of page ``index``, inherited attributes included."""
    reader = _open(pdf)[0].prev
    page_ref, _resources = reader.find_page_for_modification(index)  # type: ignore[no-untyped-call]
    page = page_ref.get_object()

    def inherited(key: str) -> Any:
        node = page
        while node is not None:
            if key in node:
                return node[key]
            # Indexing resolves the indirect reference; .get() would not.
            node = node["/Parent"] if "/Parent" in node else None  # noqa: SIM401
        return None

    box = inherited("/CropBox") or inherited("/MediaBox") or [0, 0, 612, 792]
    x1, y1, x2, y2 = (float(value) for value in box)
    rotation = int(inherited("/Rotate") or 0) % 360
    return PageGeometry(min(x1, x2), min(y1, y2), abs(x2 - x1), abs(y2 - y1), rotation)


def check_pdf_signable(pdf: bytes) -> None:
    """Raise :class:`PdfFormatError` if ``pdf`` cannot be read for signing, and
    :class:`CertifiedDocumentError` if its author forbade all changes (DocMDP, CU-03).

    Called before the PIN is requested, so neither costs the user a PIN entry.
    """
    writer, _existing = _open(pdf)
    if no_changes_allowed(writer.prev):
        raise CertifiedDocumentError("the author's certification forbids all changes")


def no_changes_allowed(reader: PdfFileReader) -> bool:
    """Whether a certification signature forbids every change (DocMDP P=1)."""
    try:
        info = read_certification_data(reader)
    except (PdfError, KeyError, ValueError, TypeError):
        return False  # unreadable certification data: pyHanko decides when signing
    return info is not None and info.permission is MDPPerm.NO_CHANGES


def _required[T](value: T | None, level: SignatureLevel, what: str) -> T:
    if value is None:
        raise ValueError(f"{level.value} needs {what}")
    return value


def _next_name(prefix: str, existing: set[str]) -> str:
    return next(
        f"{prefix}{n}" for n in range(1, len(existing) + 2) if f"{prefix}{n}" not in existing
    )


def _add_validation_info(pdf: bytes, field_name: str, context: ValidationContext) -> bytes:
    reader = PdfFileReader(io.BytesIO(pdf), strict=False)
    sig = next(s for s in reader.embedded_signatures if s.field_name == field_name)
    output = io.BytesIO()
    asyncio.run(async_add_validation_info(sig, context, output=output))
    return output.getvalue()


def _add_document_timestamp(
    pdf: bytes, timestamper: TimeStamper, context: ValidationContext, digest: str
) -> bytes:
    writer, existing = _open(pdf)
    stamper = signers.PdfTimeStamper(
        timestamper, field_name=_next_name(_TIMESTAMP_PREFIX, existing)
    )
    output = asyncio.run(stamper.async_timestamp_pdf(writer, digest, validation_context=context))
    return output.getvalue()  # type: ignore[no-any-return]


def sign_pdf_pades(
    pdf: bytes,
    token: TokenSigner,
    chain: Sequence[x509.Certificate],
    options: PadesOptions | None = None,
    *,
    level: SignatureLevel = SignatureLevel.B_B,
    timestamper: TimeStamper | None = None,
    validation_context: ValidationContext | None = None,
) -> PadesResult:
    """Return ``pdf`` with a new PAdES signature of ``level``, appended as incremental updates.

    ``chain`` goes from the trust anchor to the signer certificate (as returned by
    :func:`berigna.core.validation.check_signer`); the anchor itself is not embedded.
    Existing signatures are preserved (RF-014). B-T and above need ``timestamper``; B-LT and
    B-LTA also ``validation_context``. A TSA failure while time-stamping the signature raises
    :class:`~berigna.core.errors.TsaError` and nothing is returned.
    """
    stamper = (
        _required(timestamper, level, "a time-stamper") if level is not SignatureLevel.B_B else None
    )
    long_term = level in (SignatureLevel.B_LT, SignatureLevel.B_LTA)
    context = _required(validation_context, level, "a validation context") if long_term else None

    opts = options or PadesOptions()
    writer, existing = _open(pdf)
    field_name = _next_name(_FIELD_PREFIX, existing)
    metadata = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm=opts.digest,
        subfilter=SigSeedSubFilter.PADES,
        reason=opts.reason,
        location=opts.location,
        contact_info=opts.contact,
    )
    signer = _TokenPdfSigner(token, chain, opts.digest)
    try:
        output = _sign(writer, metadata, signer, stamper, opts.visible, field_name)
    except TimestampRequestError as exc:
        raise TsaError(f"the TSA did not time-stamp the signature: {exc}") from exc
    except (PdfError, SigningError) as exc:
        raise PdfFormatError(f"cannot sign this PDF: {exc}") from exc
    data: bytes = output.getvalue()
    if stamper is None:
        return PadesResult(data, SignatureLevel.B_B)
    if context is None:
        return PadesResult(data, SignatureLevel.B_T)
    try:
        data = _add_validation_info(data, field_name, context)
    except _SERVICE_ERRORS as exc:
        return PadesResult(data, SignatureLevel.B_T, f"validation data not embedded: {exc}")
    if level is SignatureLevel.B_LT:
        return PadesResult(data, SignatureLevel.B_LT)
    try:
        data = _add_document_timestamp(data, stamper, context, opts.digest)
    except _SERVICE_ERRORS as exc:
        return PadesResult(data, SignatureLevel.B_LT, f"document time-stamp not added: {exc}")
    return PadesResult(data, SignatureLevel.B_LTA)


def _sign(
    writer: IncrementalPdfFileWriter,
    metadata: signers.PdfSignatureMetadata,
    signer: signers.Signer,
    stamper: TimeStamper | None,
    visible: VisibleStamp | None,
    field_name: str,
) -> io.BytesIO:
    if visible is None:
        return signers.sign_pdf(writer, metadata, signer=signer, timestamper=stamper)  # type: ignore[no-any-return]
    with tempfile.NamedTemporaryFile(suffix=".pdf") as appearance:
        appearance.write(visible.appearance)
        appearance.flush()
        style = StaticStampStyle.from_pdf_file(appearance.name, border_width=0)
        spec = SigFieldSpec(field_name, on_page=visible.page, box=visible.box)
        pdf_signer = signers.PdfSigner(
            metadata, signer, timestamper=stamper, stamp_style=style, new_field_spec=spec
        )
        return pdf_signer.sign_pdf(writer)  # type: ignore[no-any-return]


def sign_pdf_basic(
    pdf: bytes,
    token: TokenSigner,
    chain: Sequence[x509.Certificate],
    options: PadesOptions | None = None,
) -> bytes:
    """Shortcut for a PAdES B-B signature (see :func:`sign_pdf_pades`)."""
    return sign_pdf_pades(pdf, token, chain, options).data
