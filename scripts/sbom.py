#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Software bill of materials of berigna in CycloneDX 1.6 JSON (R-DES-03).

Generated from what is installed, not written by hand: the Python packages berigna needs at
run time (its requirements and theirs, without extras), each with its version and licence
as installed; when a package comes from Debian, the Debian package that installed it. Then
the system components of the ``Depends`` of the ``.deb`` (BRG-DSP-001: GTK, libadwaita,
Poppler, PC/SC) and the fonts berigna carries. The development tools are not in it.

    .venv/bin/python scripts/sbom.py -o build/sbom.cdx.json
"""

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tomllib
import uuid
from importlib import metadata
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
# Depends and Recommends of the berigna package that are not Python libraries (BRG-DSP-001
# §2; python3-pyhanko and the other python3-* are found through the Python requirements).
SYSTEM = (
    "python3",
    "python3-gi",
    "python3-gi-cairo",
    "gir1.2-gtk-4.0",
    "gir1.2-adw-1",
    "gir1.2-poppler-0.18",
    "fonts-dejavu-core",
    "pcscd",
    "libccid",
)
# Fonts in berigna.core.fonts, with their licence file (the visible signature and reports).
FONTS = {
    "Arvo": ("OFL-1.1", "OFL-Arvo.txt"),
    "Source Sans 3": ("OFL-1.1", "OFL-SourceSans3.md"),
}
_DEBIAN_PYTHON = Path("/usr/lib/python3/dist-packages")


def _run(*command: str) -> str | None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    except FileNotFoundError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _codename() -> str | None:
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        return None
    found = re.search(r"^VERSION_CODENAME=(\S+)$", text, re.MULTILINE)
    return found[1] if found else None


def _deb_version(package: str) -> str | None:
    return _run("dpkg-query", "-W", "-f=${Version}", package)


def _deb_licence(package: str) -> str | None:
    """The licence of ``Files: *`` in the package's machine-readable copyright (DEP-5)."""
    try:
        text = Path(f"/usr/share/doc/{package}/copyright").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    for paragraph in re.split(r"\n\s*\n", text):
        if re.search(r"^Files:\s*\*\s*$", paragraph, re.MULTILINE):
            found = re.search(r"^License:\s*(.+)$", paragraph, re.MULTILINE)
            return found[1].strip() if found else None
    return None


def _python_licence(dist: metadata.Distribution) -> str | None:
    if expression := dist.metadata.get("License-Expression"):
        return str(expression)
    text = (dist.metadata.get("License") or "").strip()
    if text and "\n" not in text and len(text) < 80:
        return text
    classifiers = [
        c.split(" :: ")[-1] for c in dist.metadata.get_all("Classifier") or [] if "License" in c
    ]
    return " / ".join(classifiers) or None


def _licences(name: str | None) -> list[dict[str, Any]]:
    return [{"license": {"name": name}}] if name else []


def _deb_owner(dist: metadata.Distribution) -> str | None:
    """The Debian package that installed ``dist``, if it is under dist-packages."""
    if not Path(str(dist.locate_file(""))).is_relative_to(_DEBIAN_PYTHON):
        return None
    # Debian removes RECORD, so dist.files is empty: ask dpkg for the metadata folder itself
    probe = getattr(dist, "_path", None)
    owner = _run("dpkg", "-S", str(probe)) if probe else None
    return owner.split(":", 1)[0] if owner else None


def _deb_component(package: str, codename: str | None) -> dict[str, Any] | None:
    version = _deb_version(package)
    if version is None:
        return None
    purl = f"pkg:deb/debian/{package}@{version}" + (f"?distro={codename}" if codename else "")
    return {
        "type": "library" if package != "python3" else "platform",
        "bom-ref": purl,
        "name": package,
        "version": version,
        "purl": purl,
        "licenses": _licences(_deb_licence(package)),
    }


def _needs(requirements: list[str]) -> list[str]:
    """The names of ``requirements`` that apply at run time (no extras, this platform)."""
    needs: list[str] = []
    for line in requirements:
        requirement = Requirement(line)
        if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
            continue
        needs.append(canonicalize_name(requirement.name))
    return needs


def _closure(roots: list[str]) -> dict[str, tuple[metadata.Distribution, list[str]]]:
    """Every distribution ``roots`` need at run time, with the names each requires."""
    found: dict[str, tuple[metadata.Distribution, list[str]]] = {}
    pending = list(roots)
    while pending:
        name = canonicalize_name(pending.pop())
        if name in found:
            continue
        dist = metadata.distribution(name)
        found[name] = (dist, _needs(dist.requires or []))
        pending += found[name][1]
    return found


def bom() -> dict[str, Any]:
    codename = _codename()
    # berigna's own requirements from the source, not from its installed metadata (an
    # editable install keeps the requirements of the day it was installed)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    direct = _needs(project["dependencies"])
    closure = _closure(direct)
    refs: dict[str, str] = {}
    components = []
    for name, (dist, _required) in sorted(closure.items()):
        owner = _deb_owner(dist)
        component = _deb_component(owner, codename) if owner else None
        if component is None:
            purl = f"pkg:pypi/{name}@{dist.version}"
            component = {"type": "library", "bom-ref": purl, "name": name, "purl": purl}
            component["version"] = dist.version
        component["licenses"] = component.get("licenses") or _licences(_python_licence(dist))
        component["properties"] = [{"name": "berigna:python-distribution", "value": name}]
        refs[name] = component["bom-ref"]
        components.append(component)
    for package in SYSTEM:
        if (system := _deb_component(package, codename)) is not None:
            components.append(system)
    for font, (licence, notice) in FONTS.items():
        components.append(
            {
                "type": "file",
                "bom-ref": f"font:{font}",
                "name": font,
                "licenses": [{"license": {"id": licence}}],
                "properties": [{"name": "berigna:licence-file", "value": notice}],
            }
        )
    version = str(project["version"])
    if described := _run("git", "-C", str(ROOT), "describe", "--always", "--dirty"):
        version = f"{version}+git.{described}"
    main_ref = f"pkg:generic/berigna@{version}"
    dependencies = [{"ref": main_ref, "dependsOn": [refs[n] for n in direct if n in refs]}]
    dependencies += [
        {"ref": refs[name], "dependsOn": sorted({refs[n] for n in needs if n in refs})}
        for name, (_dist, needs) in sorted(closure.items())
        if name in refs
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "scripts/sbom.py"}]},
            "component": {
                "type": "application",
                "bom-ref": main_ref,
                "name": "berigna",
                "version": version,
                "supplier": {"name": "noggalito", "contact": [{"email": "berigna@noggalito.com"}]},
                "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
                "purl": main_ref,
            },
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("-o", "--output", type=Path, help="archivo de salida (por omisión, stdout)")
    args = parser.parse_args()
    text = json.dumps(bom(), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
