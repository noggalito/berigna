# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Manual HIL check of the production DNIe v2 driver WITH the holder's PIN.

Follows docs/07-calidad/protocolo-pruebas-con-pin.md: run it in your own terminal, the PIN is
sent once, never retried, and only after an explicit [s/N] confirmation. It signs two test
digests (no documents), verifies them, closes the session and then checks from a NEW session
that the card itself refuses to sign without a PIN (6982), i.e. that power-off ended it.

    .venv/bin/python tests/hil/firmar_hash_con_pin.py
"""

import getpass
import hashlib
import sys
import time
from datetime import date

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from berigna.core.errors import PinBlockedError, PinIncorrectError
from berigna.core.token.dnie_v2 import (
    _DIGEST_INFO_PREFIX,
    _MSE_SET_SIGNATURE,
    INS_PSO,
    SW_SECURITY_NOT_SATISFIED,
    DnieV2Token,
    is_dnie_v2,
)
from berigna.core.token.pin import Pin
from berigna.core.token.transport import PcscTransport


def main() -> int:
    if not sys.stdin.isatty():
        print("Necesita una terminal interactiva. No se envió el PIN.")
        return 2
    transport = PcscTransport.open_first(is_dnie_v2)
    reader = transport.reader_name
    times: list[float] = []
    print(f"Lector: {reader} (conexión exclusiva)")
    with DnieV2Token(transport) as token:
        cert = token.signing_certificate()
        print("Certificado de firma leído (no repudio).")
        print("\nSe firmarán 2 HASH DE PRUEBA (no documentos). El PIN se envía UNA sola vez.")
        if input("¿Continuar? [s/N] ").strip().lower() != "s":
            print("Cancelado. No se envió el PIN.")
            return 1
        pin = Pin(bytearray(getpass.getpass("PIN de firma del DNIe: ").encode("ascii")))
        try:
            token.verify_pin(pin)
        except PinIncorrectError as error:
            print(f"PIN no aceptado. Intentos restantes: {error.remaining_tries}. No se reintenta.")
            return 1
        except PinBlockedError:
            print("PIN bloqueado. Desbloqueo ante RENIEC.")
            return 1
        public_key = cert.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            print("Clave pública inesperada.")
            return 1
        for n in (1, 2):
            digest = hashlib.sha256(f"berigna HIL firma {n}".encode()).digest()
            start = time.perf_counter()
            signature = token.sign_digest(digest)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            public_key.verify(
                signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
            )
            print(f"  · firma {n}: verificada ({elapsed:.0f} ms)")
    print("Sesión cerrada (tarjeta apagada).")

    # Card-level check (not available through the public API on purpose: production code must
    # never attempt PSO:CDS without a verified PIN). The APDUs still go through the allow-list.
    with DnieV2Token(PcscTransport.open_first(is_dnie_v2)) as token:
        if not token.probe_alive():
            print("El applet PKI no responde.")
            return 1
        token._transmit(_MSE_SET_SIGNATURE)
        digest_info = _DIGEST_INFO_PREFIX["sha256"] + bytes(32)
        _, sw = token._transmit(bytes([0x00, INS_PSO, 0x9E, 0x9A, len(digest_info)]) + digest_info)
    verdict = "correcto" if sw == SW_SECURITY_NOT_SATISFIED else "ERROR: la sesión seguía abierta"
    print(f"Nueva sesión sin PIN: PSO:CDS -> {sw:04X} ({verdict})")
    print("\nFila para la bitácora de PIN (regla PIN-12; revisa el alias del DNIe):")
    script = "`tests/hil/firmar_hash_con_pin.py`"
    signatures = f"2 firmas verificadas ({times[0]:.0f} y {times[1]:.0f} ms, un solo PIN)"
    print(
        f"| {date.today().isoformat()} | DNIe-01 (v2) | {reader} | {script} | 9000 "
        f"| Máximo (tras un acierto) | {signatures}; nueva sesión sin PIN: PSO:CDS -> {sw:04X} |"
    )
    return 0 if sw == SW_SECURITY_NOT_SATISFIED else 1


if __name__ == "__main__":
    sys.exit(main())
