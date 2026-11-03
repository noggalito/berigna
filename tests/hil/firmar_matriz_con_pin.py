# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Manual HIL check: the format matrix of Phase 4 signed with the real DNIe and ONE PIN.

Criterion of exit of Phase 4 (increment 8, BRG-CAL-006 §4). Follows
docs/07-calidad/protocolo-pruebas-con-pin.md. With one batch (core.batch.sign_batch, one
VERIFY), at the chosen level, it signs:

- a TEST PDF in PAdES;
- a text file in CAdES detached (.p7s) and enveloping (.p7m);
- an XML document in XAdES enveloped, enveloping and detached (.xsig);
- an XML document whose root carries ``xml:lang`` in XAdES enveloped (BRG-CAL-006 §3.8).

The signed files carry the holder's name: the folder must be OUTSIDE the repository. Then
validate each in Firma Perú (https://apps.firmaperu.gob.pe/web/validador.xhtml; the .p7s and
the .xsig with their original) and, if the DSS harness is built, with
tests/interop/matriz_dss.sh (with the root of RENIEC as anchor instead of the test root).

    .venv/bin/python tests/hil/firmar_matriz_con_pin.py ~/berigna-pruebas/matriz
    .venv/bin/python tests/hil/firmar_matriz_con_pin.py ~/berigna-pruebas/matriz-lta \
        --nivel B-LTA --tsa http://timestamp.digicert.com --anclas-usuario DIR

Levels above B-B need a TSA (--tsa), as in firmar_pdf_con_pin.py: while no Peruvian TSA is
contracted (DP-02), a TSA outside the IOFE is trusted for the test with --anclas-usuario.
"""

import argparse
import getpass
import hashlib
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path

from berigna.core.batch import Outcome, sign_batch
from berigna.core.errors import BerignaError
from berigna.core.formats.cades import CadesPackaging
from berigna.core.formats.pades import PadesOptions, SignatureLevel
from berigna.core.formats.xades import XadesPackaging
from berigna.core.net.tsa import TsaSettings, http_timestamper
from berigna.core.signing import Packaging, SigningJob, signed_output_path
from berigna.core.token.dnie_v2 import DnieV2Token, is_dnie_v2
from berigna.core.token.pin import Pin
from berigna.core.token.transport import PcscTransport
from berigna.core.trust import TrustStore
from berigna.core.validation import SignerCheck

REPOSITORY = Path(__file__).resolve().parents[2]
TODAY = date.today().isoformat()
TEXT = f"Archivo de prueba de berigna (CAdES) - {TODAY}\n".encode()
XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    f'<prueba fecha="{TODAY}"><texto>Documento de prueba de berigna (XAdES)</texto></prueba>\n'
).encode()
XML_LANG = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    f'<prueba xml:lang="es-PE" fecha="{TODAY}"><texto>Raíz con xml:lang</texto></prueba>\n'
).encode()


def _test_pdf() -> bytes:
    sys.path.insert(0, str(REPOSITORY / "tests"))
    from support.pki import minimal_pdf

    return minimal_pdf(f"Documento de prueba de berigna - {TODAY}")


def _sources(folder: Path) -> list[tuple[Path, bytes, Packaging, str]]:
    """Each file to sign, its packaging and the suffix of its output."""
    pdf = folder / "matriz-pades.pdf"
    text = folder / "matriz-cades.txt"
    xml = folder / "matriz-xades.xml"
    lang = folder / "matriz-xades-xml-lang.xml"
    return [
        (pdf, _test_pdf(), None, "-firmado"),
        (text, TEXT, CadesPackaging.DETACHED, ""),
        (text, TEXT, CadesPackaging.ENVELOPING, ""),
        (xml, XML, XadesPackaging.ENVELOPED, "-envuelta"),
        (xml, XML, XadesPackaging.ENVELOPING, "-envolvente"),
        (xml, XML, XadesPackaging.DETACHED, ""),
        (lang, XML_LANG, XadesPackaging.ENVELOPED, "-envuelta"),
    ]


def _pin_prompt(count: int, level: SignatureLevel) -> Callable[[SignerCheck], Pin | None]:
    def ask(check: SignerCheck) -> Pin | None:
        if check.only_basic_level:
            print("  ! No se pudo comprobar la revocación: solo se permite B-B.")
        else:
            print("  · Certificado válido: cadena IOFE y revocación comprobadas en línea.")
        print(
            f"\nSe firmarán {count} archivos DE PRUEBA en {level.value}. El PIN se envía UNA vez."
        )
        if input("¿Continuar? [s/N] ").strip().lower() != "s":
            return None
        typed = getpass.getpass("PIN de firma del DNIe: ")
        if not typed.isascii():  # the DNIe PIN is ASCII: nothing is sent (review)
            print("El PIN solo lleva letras y números sin tildes. No se envió el PIN.")
            return None
        return Pin(bytearray(typed.encode("ascii")))

    return ask


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("carpeta", type=Path, help="carpeta vacía FUERA del repositorio")
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
        print("Las firmas llevan datos personales: elige una carpeta FUERA del repositorio.")
        return 2
    if not sys.stdin.isatty():
        print("Necesita una terminal interactiva. No se envió el PIN.")
        return 2
    if folder.exists() and any(folder.iterdir()):
        print(f"{folder} no está vacía; elige otra carpeta.")
        return 2
    folder.mkdir(parents=True, exist_ok=True)

    jobs: list[SigningJob] = []
    taken: set[Path] = set()
    for source, data, packaging, suffix in _sources(folder):
        source.write_bytes(data)
        output = signed_output_path(source, packaging, suffix, taken=frozenset(taken))
        taken.add(output)
        digest = hashlib.sha256(data).hexdigest()
        jobs.append(SigningJob(source, output, digest, packaging=packaging))

    store = TrustStore.load_bundled()
    if args.anclas_usuario:
        store = store.with_user_anchors(args.anclas_usuario.expanduser())
    timestamper = http_timestamper(TsaSettings(args.tsa, timeout=15)) if args.tsa else None
    try:  # no reader or no DNIe is an ERR-1xx too, not a traceback (review)
        transport = PcscTransport.open_first(is_dnie_v2)
        print(f"Lector: {transport.reader_name} (conexión exclusiva)")
        with DnieV2Token(transport) as token:
            items = sign_batch(
                jobs,
                token=token,
                store=store,
                ask_pin=_pin_prompt(len(jobs), level),
                options=PadesOptions(reason=f"Prueba de berigna ({level.value})", location="Perú"),
                level=level,
                timestamper=timestamper,
                online=True,
            )
    except BerignaError as error:
        print(f"No se firmó nada: {error.code} {error}")
        return 1
    print("Sesión cerrada (tarjeta apagada).\n")
    print("| Archivo | Resultado | Nivel | SHA-256 |")
    print("|---|---|---|---|")
    for item in items:
        result = item.result
        if item.outcome is Outcome.SIGNED and result is not None:
            note = f" ({result.level_note})" if result.level_note else ""
            print(
                f"| {result.output.name} | firmado | {result.level.value}{note} | {result.sha256} |"
            )
        else:
            print(f"| {item.job.output.name} | {item.outcome.value}: {item.code} | | |")
    print("\nValida cada archivo en https://apps.firmaperu.gob.pe/web/validador.xhtml")
    print("(la .p7s con matriz-cades.txt y la .xsig con matriz-xades.xml).")
    print("\nFila para la bitácora de PIN (regla PIN-12; revisa el alias del DNIe):")
    print(
        f"| {TODAY} | DNIe-01 (v2) | {transport.reader_name} | "
        f"`tests/hil/firmar_matriz_con_pin.py` | 9000 | Máximo (tras un acierto) | "
        f"Matriz de la Fase 4 en {level.value}, {len(jobs)} firmas con un PIN |"
    )
    return 0 if all(item.outcome is Outcome.SIGNED for item in items) else 1


if __name__ == "__main__":
    sys.exit(main())
