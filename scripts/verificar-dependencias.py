#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Check that the environment has the dependency versions that pyproject.toml declares.

The virtual environment sees Debian's packages (--system-site-packages, ADR-0013), so pip
never checks their versions: a Debian with another pyhanko-certvalidator would run the tests
against a library berigna was not written for (DP-19, R-DES-16). Exits 1 naming each
dependency that is missing or outside its bounds.

    .venv/bin/python scripts/verificar-dependencias.py
"""

import sys
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from packaging.requirements import Requirement

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def problems(requirements: list[str]) -> list[str]:
    found = []
    for line in requirements:
        requirement = Requirement(line)
        try:
            installed = version(requirement.name)
        except PackageNotFoundError:
            found.append(f"{requirement.name}: no está instalado (se pide {requirement})")
            continue
        if not requirement.specifier.contains(installed, prereleases=True):
            found.append(f"{requirement.name} {installed}: fuera de los límites ({requirement})")
    return found


def main() -> int:
    with PYPROJECT.open("rb") as file:
        requirements = tomllib.load(file)["project"]["dependencies"]
    found = problems(requirements)
    for problem in found:
        print(f"verificar-dependencias: {problem}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
