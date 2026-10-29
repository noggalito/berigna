# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Manual HIL check of the full PAdES flow WITH the holder's PIN (B-B to B-LTA).

Follows docs/07-calidad/protocolo-pruebas-con-pin.md. It creates a one-page TEST PDF, then runs
berigna.core.signing.sign_pdf_file exactly as the application will: the file is checked, the
certificate is validated online against RENIEC before the PIN, the PIN is sent once, the chip
signs and the output is written atomically. The signed PDF contains the holder's name, so it
must be written OUTSIDE the repository.

    .venv/bin/python tests/hil/firmar_pdf_con_pin.py ~/berigna-pruebas
    .venv/bin/python tests/hil/firmar_pdf_con_pin.py ~/berigna-pruebas \
        --nivel B-LTA --tsa http://timestamp.digicert.com --anclas-usuario DIR

Levels above B-B need a TSA (--tsa). While no Peruvian TSA is contracted (DP-02), a TSA outside
the IOFE can be trusted for the test by putting its root in --anclas-usuario (*.pem); without
it, the result stays at B-T and says why. The TSA is probed before the PIN is requested.
"""

import argparse
import getpass
import hashlib
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path

from berigna.core.errors import BerignaError
from berigna.core.formats.pades import PadesOptions, SignatureLevel
from berigna.core.net.tsa import TsaSettings, http_timestamper
from berigna.core.signing import sign_pdf_file
from berigna.core.token.dnie_v2 import DnieV2Token, is_dnie_v2
from berigna.core.token.pin import Pin
from berigna.core.token.transport import PcscTransport
from berigna.core.trust import TrustStore
from berigna.core.validation import SignerCheck

REPOSITORY = Path(__file__).resolve().parents[2]


def _test_pdf() -> bytes:
    sys.path.insert(0, str(REPOSITORY / "tests"))
    from support.pki import minimal_pdf

    return minimal_pdf(f"Documento de prueba de berigna - {date.today().isoformat()}")


def _pin_prompt(level: SignatureLevel) -> Callable[[SignerCheck], Pin | None]:
    def ask(check: SignerCheck) -> Pin | None:
        if check.only_basic_level:
            print("  ! No se pudo comprobar la revocación: solo se permite B-B.")
        else:
            print("  · Certificado válido: cadena IOFE y revocación comprobadas en línea.")
        if level is not SignatureLevel.B_B:
            print("  · TSA comprobada: acaba de emitir un sello de prueba.")
        print(f"\nSe firmará un PDF DE PRUEBA (PAdES {level.value}). El PIN se envía UNA sola vez.")
        if input("¿Continuar? [s/N] ").strip().lower() != "s":
            return None
        return Pin(bytearray(getpass.getpass("PIN de firma del DNIe: ").encode("ascii")))

    return ask


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("carpeta", type=Path, help="carpeta FUERA del repositorio")
    parser.add_argument("--nivel", choices=[lv.value for lv in SignatureLevel], default="B-B")
    parser.add_argument("--tsa", help="URL de la TSA (obligatoria por encima de B-B)")
    parser.add_argument("--anclas-usuario", type=Path, help="carpeta con raíces adicionales")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    level = SignatureLevel(args.nivel)
    if level is not SignatureLevel.B_B and not args.tsa:
        print(f"{level.value} necesita --tsa. No se envió el PIN.")
        return 2
    folder = args.carpeta.expanduser().resolve()
    if folder.is_relative_to(REPOSITORY):
        print("El PDF firmado lleva datos personales: elige una carpeta FUERA del repositorio.")
        return 2
    if not sys.stdin.isatty():
        print("Necesita una terminal interactiva. No se envió el PIN.")
        return 2
    folder.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    source = folder / f"berigna-prueba-{stamp}-{level.value}.pdf"
    output = folder / f"berigna-prueba-{stamp}-{level.value}-firmado.pdf"
    for path in (source, output):
        if path.exists():
            print(f"Ya existe {path}; bórralo o elige otra carpeta.")
            return 2
    data = _test_pdf()
    source.write_bytes(data)
    store = TrustStore.load_bundled()
    if args.anclas_usuario:
        store = store.with_user_anchors(args.anclas_usuario.expanduser())
    timestamper = http_timestamper(TsaSettings(args.tsa, timeout=15)) if args.tsa else None

    transport = PcscTransport.open_first(is_dnie_v2)
    print(f"Lector: {transport.reader_name} (conexión exclusiva)")
    try:
        with DnieV2Token(transport) as token:
            result = sign_pdf_file(
                source,
                output,
                expected_sha256=hashlib.sha256(data).hexdigest(),
                token=token,
                store=store,
                ask_pin=_pin_prompt(level),
                options=PadesOptions(reason=f"Prueba de berigna ({level.value})", location="Perú"),
                level=level,
                timestamper=timestamper,
                online=True,
            )
    except BerignaError as error:
        print(f"No se firmó: {error.code} {error}")
        return 1
    print("Sesión cerrada (tarjeta apagada).")
    print(f"\nPDF firmado ({result.level.value}): {result.output}")
    if result.level_note:
        print(f"  ! Nivel inferior al pedido ({level.value}): {result.level_note}")
    print(f"SHA-256: {result.sha256}")
    print("Valídalo en https://apps.firmaperu.gob.pe/web/validador.xhtml")
    print("\nFila para la bitácora de PIN (regla PIN-12; revisa el alias del DNIe):")
    print(
        f"| {stamp} | DNIe-01 (v2) | {transport.reader_name} | `tests/hil/firmar_pdf_con_pin.py` "
        f"| 9000 | Máximo (tras un acierto) | PAdES {result.level.value} con el flujo completo |"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
