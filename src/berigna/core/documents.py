# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""What kind of document the user opened, to choose between signing and verifying it.

:func:`inspect_document` reads the file once and returns its SHA-256 along with what it found,
so that signing can later check the file is still the one shown (RF-018). Only PDF is
recognised in 1.0; CAdES and XAdES come in Phase 4.
"""

import enum
import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

from pyhanko.pdf_utils.misc import PdfError
from pyhanko.pdf_utils.reader import PdfFileReader

from berigna.core.errors import UnreadableDocumentError
from berigna.core.formats.pades import no_changes_allowed

# ISO 32000 allows bytes before the header; readers accept it within the first kilobyte.
_PDF_HEADER = b"%PDF-"
_HEADER_WINDOW = 1024


class DocumentKind(enum.Enum):
    PDF = "pdf"
    OTHER = "other"


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


def inspect_document(path: Path) -> DocumentInfo:
    """Identify ``path``. Raises :class:`UnreadableDocumentError` for a damaged PDF.

    ``OSError`` (missing file, no permission) is left to the caller, which knows the path.
    """
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if _PDF_HEADER not in data[:_HEADER_WINDOW]:
        return DocumentInfo(path, DocumentKind.OTHER, len(data), digest)
    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        pages = int(reader.root["/Pages"]["/Count"])
        signatures = len(reader.embedded_signatures)
    except (PdfError, ValueError, KeyError, TypeError) as exc:
        raise UnreadableDocumentError(f"cannot read this PDF: {exc}") from exc
    locked = no_changes_allowed(reader)
    return DocumentInfo(path, DocumentKind.PDF, len(data), digest, pages, signatures, locked)
