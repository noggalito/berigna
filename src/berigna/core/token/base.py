# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Backend-independent contract for signature tokens (arquitectura-general §4)."""

from types import TracebackType
from typing import Literal, Protocol, Self

from cryptography import x509

from berigna.core.token.pin import Pin

HashAlgorithmName = Literal["sha256", "sha384", "sha512"]


class TokenSigner(Protocol):
    """A token whose private key signs inside the device; only digests leave the host.

    Implementations must close the authenticated session in :meth:`close`, also when used
    as a context manager that exits with an exception (P-09).
    """

    def signing_certificate(self) -> x509.Certificate:
        """The non-repudiation certificate used for signing (RF-004)."""
        ...

    def verify_pin(self, pin: Pin) -> None:
        """Send the PIN once. Never retries (P-06). Wipes ``pin`` in every case."""
        ...

    def sign_digest(self, digest: bytes, algorithm: HashAlgorithmName = "sha256") -> bytes:
        """Return the PKCS#1 v1.5 signature computed by the token over ``digest``."""
        ...

    def close(self) -> None: ...

    def __enter__(self) -> Self: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...
