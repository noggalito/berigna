#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Known vulnerabilities of the Debian packages berigna uses (R-DES-02), with ``debsecan``.

Debian fixes vulnerabilities without changing the upstream version, so a tool that reads
PyPI versions (``pip-audit``) gives false positives on Debian's packages: ``debsecan`` reads
the Debian security tracker instead. Only the packages of the SBOM and everything they depend
on are listed: the C libraries that parse what berigna opens (libxml2, OpenSSL, Poppler) come
in as dependencies of python3-lxml, python3-cryptography or gir1.2-poppler (review of the
increment 7); the other packages of the container are not berigna's. Informative: the list
goes to the job summary and to standard output, and the exit code is 0 unless ``debsecan``
cannot run; the CVEs left open by Debian are many and mostly not reachable from berigna, so a
person reads them.

    scripts/vulnerabilidades-debian.py --sbom build/sbom.cdx.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path


def _packages(sbom: Path) -> set[str]:
    components = json.loads(sbom.read_text(encoding="utf-8"))["components"]
    return {c["name"] for c in components if str(c.get("purl", "")).startswith("pkg:deb/")}


def _depends(package: str) -> set[str]:
    """The installed packages ``package`` depends on (Depends and Pre-Depends; of each
    alternative, the one installed)."""
    result = subprocess.run(  # noqa: S603 - fixed program, package name from dpkg
        ["dpkg-query", "-W", "-f=${Depends}, ${Pre-Depends}", package],
        capture_output=True,
        text=True,
        check=False,
    )
    names = set()
    for alternative in result.stdout.split(","):
        for choice in alternative.split("|"):
            name = choice.strip().split(" ")[0].split(":")[0]
            if name and _installed(name):
                names.add(name)
                break
    return names


def _installed(package: str) -> bool:
    result = subprocess.run(  # noqa: S603 - fixed program, package name from dpkg
        ["dpkg-query", "-W", "-f=${db:Status-Abbrev}", package],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.startswith("ii")


def closure(packages: set[str], depends: Callable[[str], set[str]] = _depends) -> set[str]:
    """``packages`` and everything they depend on, recursively."""
    found: set[str] = set()
    pending = list(packages)
    while pending:
        package = pending.pop()
        if package not in found:
            found.add(package)
            pending += depends(package) - found
    return found


def _codename() -> str:
    text = Path("/etc/os-release").read_text(encoding="utf-8")
    found = re.search(r"^VERSION_CODENAME=(\S+)$", text, re.MULTILINE)
    return found[1] if found else "trixie"


def parse(report: str, packages: set[str]) -> list[tuple[str, str, str, str]]:
    """``(cve, package, summary, fix)`` for each entry of ``debsecan --format detail`` whose
    installed package is one of ``packages``."""
    found = []
    for block in re.split(r"\n(?=CVE-|TEMP-)", report.strip()):
        lines = block.splitlines()
        if not lines:
            continue
        installed = re.search(r"installed: (\S+)", block)
        if installed is None or installed[1] not in packages:
            continue
        summary = lines[1].strip() if len(lines) > 1 else ""
        fixed = re.search(r"fixed in ([^:]+): (\S+ \S+)", block)
        fix = f"{fixed[1]}: {fixed[2]}" if fixed else "sin corrección"
        found.append((lines[0].split()[0], installed[1], summary, fix))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sbom", type=Path, required=True)
    args = parser.parse_args()
    result = subprocess.run(  # noqa: S603 - fixed program and arguments
        ["debsecan", f"--suite={_codename()}", "--format=detail"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode
    entries = parse(result.stdout, closure(_packages(args.sbom)))
    lines = [
        f"{len(entries)} vulnerabilidades conocidas en los paquetes de Debian del SBOM"
        " y sus dependencias.",
        "",
        "| CVE | Paquete | Resumen | Corrección |",
        "|---|---|---|---|",
    ]
    lines += [f"| {cve} | {pkg} | {summary} | {fix} |" for cve, pkg, summary, fix in entries]
    table = "\n".join(lines)
    print(table)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## Vulnerabilidades de Debian (debsecan)\n\n{table}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
