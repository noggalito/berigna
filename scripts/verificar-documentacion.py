#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""R-DES-05 (BRG-DES-002 §2): comprobación automática de la documentación de ``docs/``.

- Cabecera completa: tabla de control (Documento, Versión, Estado, Fecha, Responsable) en
  cada documento; las ADR llevan Estado y Fecha como viñetas (BRG-GES-001 §2).
- Fecha no anterior a la del último cambio del archivo (BRG-GES-001 §2), con un día de
  tolerancia: lo que se redacta de noche puede commitearse pasada la medianoche. En un
  clon superficial no se comprueba: sin historia no hay «último cambio» fiable.
- Identificadores citados que existen: RF, RNF y CU en los documentos de requisitos, ADR
  en los nombres de archivo de ``04-arquitectura/adr/`` y ERR en el catálogo de mensajes;
  DP solo en la forma (dos dígitos), porque su registro vive en la documentación interna
  (BRG-GES-001 §5).

Solo usa la biblioteca estándar: lo ejecuta ``scripts/verificar.sh``, local y en la CI.
"""

import re
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
DOCS = REPOSITORY / "docs"
FIELDS = ("Documento", "Versión", "Estado", "Fecha", "Responsable")
DATE = r"\d{4}-\d{2}-\d{2}"


def _known_identifiers() -> dict[str, set[str]]:
    """Los identificadores que existen, por prefijo, leídos de donde se definen."""
    requirements = DOCS / "03-requisitos"

    def headings(document: Path, pattern: str) -> set[str]:
        return set(re.findall(pattern, document.read_text(encoding="utf-8"), re.MULTILINE))

    return {
        "RF": headings(requirements / "requisitos-funcionales.md", r"^### (RF-\d{3})\b"),
        "RNF": headings(requirements / "requisitos-no-funcionales.md", r"^\| (RNF-[A-Z]+-\d+) \|"),
        "CU": headings(requirements / "casos-de-uso.md", r"^### (CU-\d+)\b"),
        "ADR": {p.stem[:8] for p in (DOCS / "04-arquitectura" / "adr").glob("ADR-????-*.md")},
        "ERR": set(
            re.findall(
                r'"(ERR-\d{3})"',
                (REPOSITORY / "src/berigna/core/report/messages.py").read_text(encoding="utf-8"),
            )
        ),
    }


def _last_change(path: Path) -> str | None:
    """La fecha de autoría del último commit que cambió ``path``, o None sin historia."""
    result = subprocess.run(  # noqa: S603 - fixed program and arguments
        ["git", "log", "-1", "--format=%aI", "--", str(path.relative_to(REPOSITORY))],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip() or None


def _is_shallow() -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=REPOSITORY,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip() == "true"


def main() -> int:
    documents = sorted(DOCS.rglob("*.md"))
    known = _known_identifiers()
    shallow = _is_shallow()
    problems: list[str] = []
    for document in documents:
        relative = document.relative_to(REPOSITORY)
        text = document.read_text(encoding="utf-8")
        header = text.split("\n## ", 1)[0]
        is_adr = document.name.startswith("ADR-")
        if is_adr:
            if not re.search(r"- Estado: \S", header):
                problems.append(f"{relative}: el ADR no dice su Estado")
            if not re.search(rf"- Fecha: ({DATE})\b", header):
                problems.append(f"{relative}: el ADR no dice su Fecha")
            dates = re.findall(rf"- Fecha: ({DATE})", header)
        else:
            fields = dict(re.findall(r"\| (\w+) \| ([^|]+) \|", header))
            if missing := [f for f in FIELDS if f not in fields]:
                problems.append(f"{relative}: a la cabecera le falta {', '.join(missing)}")
            if "Documento" in fields and not re.match(
                r"BRG-[A-Z]+-(\d{3}|ADR)$", fields["Documento"].strip()
            ):
                problems.append(f"{relative}: código de documento mal formado")
            dates = [fields["Fecha"].strip()] if "Fecha" in fields else []
        for existing, pattern in (
            (known["RF"], r"\b(RF-\d{3})\b"),
            (known["RNF"], r"\b(RNF-[A-Z]+-\d+)\b"),
            (known["CU"], r"\b(CU-\d+)\b"),
            (known["ADR"], r"\b(ADR-\d{4})\b"),
            (known["ERR"], r"\b(ERR-\d{3})\b"),
        ):
            if missing := sorted(set(re.findall(pattern, text)) - existing):
                problems.append(f"{relative}: cita {', '.join(missing)}, que no existe")
        for value in re.findall(r"\bDP-(\d+)\b", text):  # registro interno: solo la forma
            if len(value) != 2:
                problems.append(f"{relative}: cita DP-{value} con otra forma que DP-NN")
        if not shallow and dates:
            change = _last_change(document)
            if change and date.fromisoformat(change[:10]) - date.fromisoformat(
                dates[0]
            ) > timedelta(
                days=1
            ):  # un día de tolerancia: lo redactado de noche se commitea pasada la medianoche
                problems.append(f"{relative}: Fecha {dates[0]}, anterior al último cambio")
    for problem in problems:
        print(f"documentación: {problem}", file=sys.stderr)
    if shallow:
        print("documentación: clon superficial, sin comprobar fechas", file=sys.stderr)
    print(f"documentación: {len(documents)} documentos; problemas: {len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
