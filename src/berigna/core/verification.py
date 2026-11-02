# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verifying any signed file the user opens (CU-06; RF-050 to RF-052), whatever its format.

:func:`verify_document` chooses the verifier by the content, as
:func:`berigna.core.documents.detect_kind` does: PAdES for a PDF, CAdES for a CMS (``.p7s``
and ``.p7m``) and XAdES for an XML document (``.xml`` and ``.xsig``). A detached signature
needs the file it signs: :func:`is_detached` says so before verifying, and
:func:`original_of` finds the file next to it with the same name without the last extension
(RF-051), as berigna names them (``acta.xml.p7s``, ``acta.xml.xsig``).
"""

import datetime as dt
import hashlib
import re
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from berigna.core.documents import DocumentKind, detect_kind
from berigna.core.errors import UnreadableDocumentError
from berigna.core.formats.xades import DS, parse_document
from berigna.core.trust import TrustStore
from berigna.core.validation import (
    CadesSignatureReport,
    CadesVerification,
    PdfSignatureReport,
    PdfVerification,
    XadesSignatureReport,
    XadesVerification,
    verify_cades,
    verify_pdf,
    verify_xades,
)
from berigna.core.validation.cades import cades_content, signed_data_of

Verification = PdfVerification | CadesVerification | XadesVerification
SignatureReport = PdfSignatureReport | CadesSignatureReport | XadesSignatureReport

# Extensions that name a signature apart from what it signs (RF-020, RF-032).
DETACHED_SUFFIXES = (".p7s", ".xsig")


def _external_references(data: bytes) -> list[str]:
    """The URIs of the ``ds:Reference`` that point outside the document: a detached XAdES
    has some. Only called on what :func:`~berigna.core.documents.detect_kind` read as XML."""
    root = parse_document(data).getroot()
    uris = []
    for signed_info in root.iter(f"{{{DS}}}SignedInfo"):
        for reference in signed_info.iterfind(f"{{{DS}}}Reference"):
            uri = reference.get("URI")
            if uri and not uri.startswith("#"):
                uris.append(uri)
    return uris


def _kind(data: bytes, kind: DocumentKind | None) -> DocumentKind:
    return kind if kind is not None else detect_kind(data)[0]


def is_detached(data: bytes, kind: DocumentKind | None = None) -> bool:
    """Whether the signature in ``data`` signs a file it does not carry: a CAdES without its
    content (``.p7s``) or a XAdES that references a file (``.xsig``). ``kind``, when the
    caller already knows it, saves reading the file again."""
    kind = _kind(data, kind)
    if kind is DocumentKind.CADES:
        return cades_content(data) is None
    if kind is DocumentKind.XML:
        return bool(_external_references(data))
    return False


# "acta-2.xml.p7s" is the second signature of "acta.xml" (RF-045 numbers before the extension).
_NUMBERED = re.compile(r"^(?P<stem>.+)-\d+(?P<suffix>\.[^.]*)?$")


def _candidates(signature: Path, data: bytes | None) -> list[Path]:
    """Where the signed file may be, most likely first: the name a detached XAdES gives
    (only its last component, never another folder), the name without the extension, and
    that name without the number berigna adds when a signature name is taken."""
    folder, names = signature.parent, []
    if data is not None and detect_kind(data)[0] is DocumentKind.XML:
        names += [PurePosixPath(unquote(uri)).name for uri in _external_references(data)]
    if signature.suffix.lower() in DETACHED_SUFFIXES:
        stripped = signature.with_suffix("").name
        names.append(stripped)
        if numbered := _NUMBERED.match(stripped):
            names.append(numbered["stem"] + (numbered["suffix"] or ""))
    return [folder / name for name in dict.fromkeys(names) if name not in ("", ".", "..")]


def _digest_matches(signature: bytes, candidate: Path) -> bool:
    """Whether ``candidate`` has the digest the first signer of a CAdES signed; ``False``
    when either cannot be read (a damaged signature is reported by the verifier)."""
    try:
        signer_info = signed_data_of(signature)["signer_infos"][0]
        algorithm = signer_info["digest_algorithm"]["algorithm"].native
        signed = [
            attribute["values"][0].native
            for attribute in signer_info["signed_attrs"]
            if attribute["type"].native == "message_digest"
        ]
        return signed == [hashlib.new(algorithm, candidate.read_bytes()).digest()]
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        return False


def original_of(signature: Path, data: bytes | None = None) -> Path | None:
    """The file a detached signature signs, next to it (RF-051): the one a XAdES names,
    ``acta.xml`` for ``acta.xml.p7s`` or for ``acta-2.xml.p7s``. With the bytes of a CAdES,
    the one whose digest is the signed one is preferred, so that an unrelated file with
    the guessed name is not taken for it (review of the increment 6). ``None`` when there
    is no such file."""
    existing = [path for path in _candidates(signature, data) if path.is_file()]
    if data is not None and detect_kind(data)[0] is DocumentKind.CADES:
        matching = [path for path in existing if _digest_matches(data, path)]
        existing = matching or existing
    return existing[0] if existing else None


def verify_document(
    data: bytes,
    store: TrustStore,
    *,
    content: bytes | None = None,
    moment: dt.datetime | None = None,
    online: bool = True,
    ocsp_responses: Sequence[bytes] = (),
    crls: Sequence[bytes] = (),
    timeout: float = 10.0,
    kind: DocumentKind | None = None,
) -> Verification:
    """Verify every signature of ``data`` with the verifier of its format; ``content`` is the
    file a detached signature signs. Raises
    :class:`~berigna.core.errors.UnreadableDocumentError` when ``data`` is none of PDF, CMS
    or XML, and what each verifier raises. ``kind``, when the caller already knows it, saves
    reading the file again."""
    kind = _kind(data, kind)
    if kind is DocumentKind.PDF:
        return verify_pdf(
            data,
            store,
            moment=moment,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
            timeout=timeout,
        )
    if kind is DocumentKind.CADES:
        return verify_cades(
            data,
            store,
            content=content,
            moment=moment,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
            timeout=timeout,
        )
    if kind is DocumentKind.XML:
        return verify_xades(
            data,
            store,
            content=content,
            moment=moment,
            online=online,
            ocsp_responses=ocsp_responses,
            crls=crls,
            timeout=timeout,
        )
    raise UnreadableDocumentError("not a PDF, a CMS signature or an XML document")
