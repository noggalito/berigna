#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Check the dependency versions that pyproject.toml declares, in two places.

The environment: the virtual environment sees Debian's packages (--system-site-packages,
ADR-0013), so pip never checks their versions: a Debian with another pyhanko-certvalidator
would run the tests against a library berigna was not written for (DP-19, R-DES-16).

The package: the Depends of berigna in debian/control carries the same bounds, so that apt
refuses a distribution that does not meet them (Ubuntu 24.04, Linux Mint 22) instead of
berigna failing when it signs. One .deb serves the whole Debian family (ADR-0023).

Exits 1 naming each dependency that is missing or outside its bounds, and each bound that
debian/control does not repeat.

    .venv/bin/python scripts/verificar-dependencias.py
"""

import re
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
CONTROL = ROOT / "debian" / "control"
# The Debian name of each project whose name is not python3-<name>.
DEBIAN_NAMES = {"pillow": "python3-pil"}


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


def _next(release: str, part: int) -> str:
    """``release`` cut after ``part`` components, the last one raised by one."""
    numbers = [int(number) for number in release.split(".")[: part + 1]]
    numbers[-1] += 1
    return ".".join(map(str, numbers))


def debian_relations(line: str) -> tuple[str, set[tuple[str, str]]]:
    """The Debian package of a requirement and the version relations it needs in Depends.

    ``>=V`` is ``(>= V)``; ``~=V`` adds the upper bound of PEP 440 (``~=0.26.3`` is
    ``(>= 0.26.3), (<< 0.27)``); ``==V`` allows the fixes of V's minor release, ``(>= V),
    (<< next minor)``: Debian's versions carry a revision that ``=`` would have to name.
    """
    requirement = Requirement(line)
    name = requirement.name.lower()
    package = DEBIAN_NAMES.get(name, f"python3-{name}")
    relations = set()
    for spec in requirement.specifier:
        if spec.operator == ">=":
            relations.add((">=", spec.version))
        elif spec.operator == "~=":
            relations.add((">=", spec.version))
            relations.add(("<<", _next(spec.version, len(spec.version.split(".")) - 2)))
        elif spec.operator == "==":
            relations.add((">=", spec.version))
            relations.add(("<<", _next(spec.version, 1)))
        else:
            raise ValueError(f"{line}: operador sin equivalente en Debian ({spec.operator})")
    return package, relations


def depends(control: str, package: str = "berigna") -> dict[str, set[tuple[str, str]]]:
    """The version relations of each dependency of ``package`` in a debian/control."""
    lines = [line for line in control.splitlines() if not line.startswith("#")]
    stanza = re.search(rf"^Package: {package}\n(.*?)(?:\n\n|\Z)", "\n".join(lines), re.M | re.S)
    if stanza is None:
        raise ValueError(f"debian/control no tiene el paquete {package}")
    field = re.search(r"^Depends:(.*?)(?=^\S|\Z)", stanza.group(1), re.M | re.S)
    found: dict[str, set[tuple[str, str]]] = {}
    for item in (field.group(1) if field else "").split(","):
        match = re.fullmatch(r"\s*([a-z0-9.+-]+)\s*(?:\((<<|<=|=|>=|>>)\s*([^)\s]+)\))?\s*", item)
        if match is None:
            continue  # substitution variables such as ${misc:Depends}
        name, operator, version = match.groups()
        found.setdefault(name, set())
        if operator:
            found[name].add((operator, version))
    return found


def control_problems(requirements: list[str], control: str) -> list[str]:
    declared = depends(control)
    found = []
    for line in requirements:
        package, wanted = debian_relations(line)
        if package not in declared:
            found.append(f"debian/control: falta {package} en el Depends de berigna ({line})")
        elif declared[package] != wanted:
            relations = ", ".join(f"({op} {version})" for op, version in sorted(wanted, key=lambda r: r[0] != ">="))
            found.append(f"debian/control: {package} debe llevar {relations} ({line})")
    return found


def main() -> int:
    with PYPROJECT.open("rb") as file:
        requirements = tomllib.load(file)["project"]["dependencies"]
    found = problems(requirements) + control_problems(requirements, CONTROL.read_text())
    for problem in found:
        print(f"verificar-dependencias: {problem}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
