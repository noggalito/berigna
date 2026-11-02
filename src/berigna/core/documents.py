# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""What kind of document the user opened, to choose between signing and verifying it.

:func:`inspect_document` reads the file once and returns its SHA-256 along with what it found,
so that signing can later check the file is still the one shown (RF-018). It recognises PDF,
XML (signed with XAdES or not) and CAdES signatures (``.p7s`` and ``.p7m``) by their content,
not by the extension; anything else is a file to sign in CAdES (CU-05).
"""

import codecs
import enum
import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

from lxml import etree
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader

from berigna.core.errors import UnreadableDocumentError, UnreadableSignatureError
from berigna.core.formats.pades import no_changes_allowed
from berigna.core.formats.xades import NS, parse_document
from berigna.core.validation.cades import signed_data_of

# ISO 32000 allows bytes before the header; readers accept it within the first kilobyte.
_PDF_HEADER = b"%PDF-"
_HEADER_WINDOW = 1024  # where the header may start; it may end a few bytes later
_BOMS = (codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
# Control characters that never appear in text: their presence makes a file binary.
_BINARY = frozenset(range(0x20)) - {0x09, 0x0A, 0x0C, 0x0D}
TEXT_PREVIEW_LIMIT = 64 * 1024  # what the text view shows of a large file (CU-05 step 3)


class DocumentKind(enum.Enum):
    PDF = "pdf"
    XML = "xml"  # signed in XAdES; ``signatures`` counts its ``ds:Signature`` elements
    CADES = "cades"  # a CMS signed-data: a ``.p7s`` or a ``.p7m``
    OTHER = "other"  # any other file: signed in CAdES


@dataclass(frozen=True)
class DocumentInfo:
    path: Path
    kind: DocumentKind
    size: int
    sha256: str
    pages: int | None = None  # PDF only
    signatures: int = 0  # signature fields with a value, document timestamps included
    locked: bool = False  # certified by its author with no changes allowed (DocMDP P=1)

    @property
    def signed(self) -> bool:
        return self.signatures > 0


def _looks_like_xml(data: bytes) -> bool:
    for bom in _BOMS:
        if data.startswith(bom):
            return True
    return data.lstrip()[:1] == b"<"


def _xml_signatures(data: bytes) -> int | None:
    """How many ``ds:Signature`` the XML document carries; ``None`` when it is not XML."""
    if not _looks_like_xml(data):
        return None
    try:
        tree = parse_document(data)
    except UnreadableDocumentError:
        return None
    root = tree.getroot()
    found = root.xpath("count(descendant-or-self::ds:Signature)", namespaces=NS)
    return int(found) if isinstance(found, float) else 0


def _cms_signatures(data: bytes) -> int | None:
    """How many signers the CMS signed-data has; ``None`` when it is not one."""
    if data[:1] != b"\x30":  # a DER SEQUENCE: saves parsing every other file
        return None
    try:
        # asn1crypto parses lazily: a damaged body only fails when it is read
        return len(signed_data_of(data)["signer_infos"])
    except (UnreadableSignatureError, ValueError, TypeError, KeyError):
        return None


def detect_kind(data: bytes) -> tuple[DocumentKind, int]:
    """The kind of ``data`` and its signatures, without the PDF details (batch lists, RF-041).
    A PDF says 0 signatures here: :func:`inspect_document` counts them. The CMS goes first:
    a ``.p7m`` of a PDF carries the PDF header within its first kilobyte (review of the
    increment 6)."""
    if (count := _cms_signatures(data)) is not None:
        return DocumentKind.CADES, count
    if _PDF_HEADER in data[: _HEADER_WINDOW + len(_PDF_HEADER) - 1]:
        return DocumentKind.PDF, 0
    if (count := _xml_signatures(data)) is not None:
        return DocumentKind.XML, count
    return DocumentKind.OTHER, 0


def inspect_document(path: Path) -> DocumentInfo:
    """Identify ``path``. Raises :class:`UnreadableDocumentError` for a damaged PDF.

    ``OSError`` (missing file, no permission) is left to the caller, which knows the path.
    """
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    kind, signatures = detect_kind(data)
    if kind is not DocumentKind.PDF:
        return DocumentInfo(path, kind, len(data), digest, signatures=signatures)
    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        pages = int(reader.root["/Pages"]["/Count"])
        signatures = len(reader.embedded_signatures)
    except (PdfError, ValueError, KeyError, TypeError) as exc:
        raise UnreadableDocumentError(f"cannot read this PDF: {exc}") from exc
    locked = no_changes_allowed(reader)
    return DocumentInfo(path, DocumentKind.PDF, len(data), digest, pages, signatures, locked)


@dataclass(frozen=True)
class TextPreview:
    text: str
    truncated: bool  # only the first TEXT_PREVIEW_LIMIT bytes are shown


def _xml_encoding(data: bytes) -> str | None:
    """The encoding an XML declaration names (``ISO-8859-1``), if any and known to Python."""
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
        declared = str(etree.parse(io.BytesIO(data), parser).docinfo.encoding)
    except etree.XMLSyntaxError:
        return None
    try:
        codecs.lookup(declared)
    except LookupError:
        return None
    return declared


def text_preview(data: bytes, limit: int = TEXT_PREVIEW_LIMIT) -> TextPreview | None:
    """The text of ``data`` if it is a text file, for the view of CU-05 (WYSIWYS): UTF-8
    (with or without BOM), UTF-16 with BOM, or the encoding an XML declaration names.
    ``None`` for a binary file, which the user checks by its name, size and SHA-256."""
    sample = data[:limit]
    truncated = len(data) > limit
    encodings = ["utf-8-sig"]
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encodings = ["utf-16"]
    elif _looks_like_xml(data) and (declared := _xml_encoding(data)):
        encodings.insert(0, declared)
    for encoding in encodings:
        decoder = codecs.getincrementaldecoder(encoding)()
        try:
            # final only when the whole file is here: a sample may end inside a character
            text = decoder.decode(sample, final=not truncated)
        except UnicodeDecodeError:
            continue
        if any(ord(char) in _BINARY for char in text):
            return None
        return TextPreview(text, truncated)
    return None
