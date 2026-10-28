# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Own trust store for signature validation (ADR-0009).

The bundled anchors (roots and intermediates of the ROOT 3 and ROOT 5 hierarchies) are checked
against ``anchors/manifest.json`` on every load: a certificate whose SHA-256 differs from the
manifest, or a file not listed in it, makes the whole store unusable (AM-08, CS-08). User
anchors (RF-061) are kept apart and flagged so that reports can say so.
"""

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Literal, Self

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from berigna.core.errors import InvalidAnchorError, TrustStoreIntegrityError

Role = Literal["root", "intermediate"]
_MANIFEST = "manifest.json"


@dataclass(frozen=True)
class TrustedCertificate:
    certificate: x509.Certificate
    role: Role
    hierarchy: str
    user_added: bool = False

    @property
    def sha256(self) -> str:
        return _fingerprint(self.certificate)


def _fingerprint(certificate: x509.Certificate) -> str:
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        return bool(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _is_self_issued(certificate: x509.Certificate) -> bool:
    return certificate.subject == certificate.issuer


class TrustStore:
    """Immutable set of trusted roots and helper intermediates."""

    def __init__(self, entries: Sequence[TrustedCertificate]) -> None:
        self._entries = tuple(entries)

    @classmethod
    def load_bundled(cls) -> Self:
        """Load the anchors shipped inside the package, verifying them against the manifest."""
        with resources.as_file(resources.files("berigna.core.trust") / "anchors") as directory:
            return cls.load_directory(directory)

    @classmethod
    def load_directory(cls, directory: Path) -> Self:
        manifest_path = directory / _MANIFEST
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            listed = {item["file"]: item for item in manifest["certificates"]}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise TrustStoreIntegrityError(f"unreadable trust manifest: {exc}") from exc

        present = {path.name for path in directory.glob("*.pem")}
        if present != set(listed):
            unexpected = sorted(present ^ set(listed))
            raise TrustStoreIntegrityError(f"files and manifest disagree: {unexpected}")

        entries = []
        for name, item in sorted(listed.items()):
            certificate = x509.load_pem_x509_certificate((directory / name).read_bytes())
            if _fingerprint(certificate) != item.get("sha256"):
                raise TrustStoreIntegrityError(f"{name}: SHA-256 does not match the manifest")
            role = item.get("role")
            if role not in ("root", "intermediate") or not _is_ca(certificate):
                raise TrustStoreIntegrityError(f"{name}: not a CA certificate with a valid role")
            if (role == "root") != _is_self_issued(certificate):
                raise TrustStoreIntegrityError(f"{name}: role does not match the certificate")
            entries.append(TrustedCertificate(certificate, role, str(item.get("hierarchy", ""))))
        return cls(entries)

    def with_user_anchors(self, directory: Path) -> Self:
        """Return a store extended with the user's own roots (``*.pem`` in ``directory``)."""
        extra = []
        for path in sorted(directory.glob("*.pem")) if directory.is_dir() else ():
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
            if not _is_ca(certificate):
                raise InvalidAnchorError(f"{path.name}: not a CA certificate")
            extra.append(TrustedCertificate(certificate, "root", "usuario", user_added=True))
        return type(self)((*self._entries, *extra))

    @property
    def entries(self) -> tuple[TrustedCertificate, ...]:
        return self._entries

    @property
    def roots(self) -> list[x509.Certificate]:
        return self._select(entry for entry in self._entries if entry.role == "root")

    @property
    def intermediates(self) -> list[x509.Certificate]:
        return self._select(entry for entry in self._entries if entry.role == "intermediate")

    def is_user_anchor(self, certificate: x509.Certificate) -> bool:
        fingerprint = _fingerprint(certificate)
        return any(e.user_added and e.sha256 == fingerprint for e in self._entries)

    @staticmethod
    def _select(entries: Iterable[TrustedCertificate]) -> list[x509.Certificate]:
        return [entry.certificate for entry in entries]
