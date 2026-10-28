# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""PAdES signatures with pyHanko 0.25.x; the private-key operation happens in the token.

Only the PAdES baseline B-B level (no timestamp) is produced here for now; B-T, B-LT and
B-LTA come in Phase 2 with the TSA client and the embedding of validation data.
"""

import hashlib
import io
from collections.abc import Sequence
from dataclasses import dataclass

from asn1crypto import algos
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter, enumerate_sig_fields
from pyhanko.sign.general import SigningError
from pyhanko_certvalidator.registry import SimpleCertificateStore

from berigna.core.errors import PdfFormatError
from berigna.core.token.base import HashAlgorithmName, TokenSigner

_SIGNATURE_SIZE = 256  # RSA-2048 (DNIe v2, SPK-01)
_FIELD_PREFIX = "FirmaBerigna"


@dataclass(frozen=True)
class PadesOptions:
    """Optional signature dictionary entries (RF-013)."""

    reason: str | None = None
    location: str | None = None
    contact: str | None = None
    digest: HashAlgorithmName = "sha256"


def _to_asn1(certificate: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))


def _registry(certificates: Sequence[x509.Certificate]) -> SimpleCertificateStore:
    store = SimpleCertificateStore()  # type: ignore[no-untyped-call]
    for certificate in certificates:
        store.register(_to_asn1(certificate))
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
            signing_cert=_to_asn1(chain[-1]),
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


def check_pdf_signable(pdf: bytes) -> None:
    """Raise :class:`PdfFormatError` if ``pdf`` cannot be read for signing.

    Called before the PIN is requested, so a damaged file does not cost the user a PIN entry.
    """
    _open(pdf)


def sign_pdf_basic(
    pdf: bytes,
    token: TokenSigner,
    chain: Sequence[x509.Certificate],
    options: PadesOptions | None = None,
) -> bytes:
    """Return ``pdf`` with a new PAdES B-B signature appended as an incremental update.

    ``chain`` goes from the trust anchor to the signer certificate (as returned by
    :func:`berigna.core.validation.check_signer`); the anchor itself is not embedded.
    Existing signatures are preserved (RF-014).
    """
    opts = options or PadesOptions()
    writer, existing = _open(pdf)
    field_name = next(
        f"{_FIELD_PREFIX}{n}"
        for n in range(1, len(existing) + 2)
        if f"{_FIELD_PREFIX}{n}" not in existing
    )
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
        output = signers.sign_pdf(writer, metadata, signer=signer)
    except (PdfError, SigningError) as exc:
        raise PdfFormatError(f"cannot sign this PDF: {exc}") from exc
    return output.getvalue()  # type: ignore[no-any-return]
