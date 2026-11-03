#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Performance measurements with the simulated card (R-DES-10, RNF-REN).

Measures what a user waits for: signing a 10 MB PDF (RNF-REN-02), a batch of 20 PDFs,
verifying a PDF B-LTA offline and reading a folder of 200 PDFs of 200 kB as the batch page
does (the reading that M-1 found in the main thread). Each
time is divided by a calibration workload measured on the same machine, so that a reference
taken on one computer can be compared with a run on another (the CI runners differ from run
to run). A measure more than 50 % slower than the reference is a warning, never a failure:
times on shared runners are noisy, and the warning asks a person to look.

    .venv/bin/python scripts/rendimiento.py                 # measure and compare
    .venv/bin/python scripts/rendimiento.py --actualizar    # also write the new reference

On GitHub Actions the warnings are annotations (``::warning::``) and the table goes to the
job summary.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

import io  # noqa: E402

from pyhanko.pdf_utils import generic  # noqa: E402
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter  # noqa: E402

from berigna.core.batch import collect_files, read_files, sign_batch  # noqa: E402
from berigna.core.signing import SigningJob  # noqa: E402
from berigna.core.token.dnie_v2 import DnieV2Token  # noqa: E402
from berigna.core.validation import Indication, verify_pdf  # noqa: E402
from sim.dnie_v2 import DnieV2Simulator  # noqa: E402
from support.cards import make_card  # noqa: E402
from support.pki import Pki, build_pki, minimal_pdf  # noqa: E402
from support.prompts import PinPrompt  # noqa: E402
from support.signed import pades  # noqa: E402

REFERENCE = ROOT / "tests" / "data" / "rendimiento" / "referencia.json"
TOLERANCE = 1.5  # R-DES-10: a warning when a measure is more than 50 % slower
REPEATS = 3  # the fastest of three: the others measure the machine, not berigna


def _calibration() -> None:
    """A fixed mix of what berigna spends its time on: Python objects (pyHanko and asn1crypto
    parse in pure Python) and hashing."""
    table: dict[int, str] = {}
    for number in range(300_000):
        table[number] = str(number)
    sum(len(text) for text in table.values())
    hashlib.sha256(bytes(16 * 1024 * 1024)).digest()


def _pdf_of(size: int) -> bytes:
    """A PDF of about ``size`` bytes: a minimal one with an incompressible stream added."""
    writer = IncrementalPdfFileWriter(io.BytesIO(minimal_pdf()))
    stream = generic.StreamObject(stream_data=os.urandom(size))
    writer.add_object(stream)
    out = io.BytesIO()
    writer.write(out)  # type: ignore[no-untyped-call]
    return out.getvalue()


def _signer(pki: Pki) -> Callable[[list[Path]], None]:
    """Sign with one simulated card made once: generating its RSA key and the OCSP answer is
    test setup, not what the user waits for, and its time varies a lot (review)."""
    card, leaf = make_card(pki, "FIRMANTE RENDIMIENTO")
    ocsp = pki.ocsp(leaf)
    files, key = dict(card.files), card.private_key  # a closed session powers the card off

    def sign(sources: list[Path]) -> None:
        jobs = []
        for source in sources:
            data = source.read_bytes()
            output = source.with_name(f"{source.stem}-firmado-{time.monotonic_ns()}.pdf")
            jobs.append(SigningJob(source, output, hashlib.sha256(data).hexdigest()))
        with DnieV2Token(DnieV2Simulator(files=dict(files), private_key=key)) as token:
            items = sign_batch(
                jobs,
                token=token,
                store=pki.store,
                ask_pin=PinPrompt(),
                online=False,
                ocsp_responses=[ocsp],
            )
        failed = [item for item in items if item.result is None]
        if failed:
            raise SystemExit(f"la firma falló: {failed[0].code} {failed[0].detail}")

    return sign


def measures(folder: Path) -> dict[str, Callable[[], object]]:
    pki = build_pki()
    sign = _signer(pki)
    large = folder / "grande.pdf"
    large.write_bytes(_pdf_of(10 * 1024 * 1024))
    batch = folder / "lote"
    batch.mkdir()
    documents = [batch / f"documento-{number:02}.pdf" for number in range(1, 21)]
    for number, document in enumerate(documents, 1):
        document.write_bytes(minimal_pdf(f"Documento {number}"))
    many = folder / "carpeta"
    many.mkdir()
    page = _pdf_of(200 * 1024)  # an ordinary scanned page: the hash counts, as in M-1
    for number in range(1, 201):
        (many / f"acta-{number:03}.pdf").write_bytes(page)
    lta, _tsa = pades(pki, "B-LTA")

    def verify() -> None:
        result = verify_pdf(lta, pki.store, online=False)
        if result.signatures[0].indication is not Indication.TOTAL_PASSED:
            raise SystemExit("la verificación del PDF B-LTA no dio TOTAL-PASSED")

    return {
        "firmar_pdf_10_mb": lambda: sign([large]),
        "firmar_lote_20_pdf": lambda: sign(documents),
        "verificar_pdf_b_lta": verify,
        "leer_carpeta_200_pdf": lambda: read_files(collect_files([many], recursive=False)),
    }


def _fastest(action: Callable[[], object]) -> float:
    times = []
    for _ in range(REPEATS):
        start = time.perf_counter()
        action()
        times.append(time.perf_counter() - start)
    return min(times)


Result = dict[str, dict[str, float]]


def run() -> tuple[float, Result]:
    calibration = _fastest(_calibration)
    seconds: dict[str, float] = {}
    with tempfile.TemporaryDirectory(prefix="berigna-rendimiento-") as tmp:
        for name, action in measures(Path(tmp)).items():
            seconds[name] = _fastest(action)
    return calibration, {
        "segundos": {name: round(value, 4) for name, value in seconds.items()},
        "relativo": {name: round(value / calibration, 4) for name, value in seconds.items()},
    }


def compare(current: Result, reference: Result) -> list[str]:
    """The measures more than :data:`TOLERANCE` times slower than the reference."""
    now, before = current["relativo"], reference["relativo"]
    return [
        f"{name}: {now[name] / before[name]:.2f} veces el tiempo de referencia"
        for name in now
        if before.get(name, 0) > 0 and now[name] > before[name] * TOLERANCE
    ]


def _table(calibration: float, current: Result, reference: Result | None) -> str:
    seconds, relative = current["segundos"], current["relativo"]
    before = reference["relativo"] if reference else {}
    lines = [
        f"Calibración: {calibration:.4f} s",
        "",
        "| Medida | Segundos | Relativo | Referencia | Cambio |",
        "|---|---|---|---|---|",
    ]
    for name, value in seconds.items():
        ref = before.get(name)
        change = f"{relative[name] / ref:.2f} veces" if ref else "—"  # 0 or missing: no ratio
        lines.append(f"| {name} | {value} | {relative[name]} | {ref or '—'} | {change} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--actualizar", action="store_true", help="escribir la referencia")
    args = parser.parse_args()
    calibration, current = run()
    reference = json.loads(REFERENCE.read_text()) if REFERENCE.exists() else None
    table = _table(calibration, current, reference)
    print(table)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## Rendimiento (R-DES-10)\n\n{table}\n")
    slower = compare(current, reference) if reference else []
    for warning in slower:
        prefix = "::warning title=Rendimiento (R-DES-10)::" if os.environ.get("CI") else "Aviso: "
        print(prefix + warning)
    if args.actualizar:
        REFERENCE.parent.mkdir(parents=True, exist_ok=True)
        REFERENCE.write_text(json.dumps(current, indent=2, ensure_ascii=False) + "\n")
        print(f"Referencia escrita en {REFERENCE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
