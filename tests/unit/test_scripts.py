# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The development scripts of the increment 7 of Phase 4: the SBOM (R-DES-03) and the
performance comparison (R-DES-10)."""

import importlib.util
import tomllib
from pathlib import Path
from types import ModuleType

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]


def _script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / name)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_sbom_lists_what_berigna_needs_at_run_time() -> None:
    sbom = _script("sbom.py")
    bom = sbom.bom()
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.6")
    assert bom["metadata"]["component"]["name"] == "berigna"
    distributions = {
        prop["value"]
        for component in bom["components"]
        for prop in component.get("properties", [])
        if prop["name"] == "berigna:python-distribution"
    }
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    direct = {canonicalize_name(Requirement(line).name) for line in project["dependencies"]}
    assert direct <= distributions
    assert "pyhanko-certvalidator" in distributions  # and what they need
    assert not {"pytest", "mypy", "ruff", "hypothesis"} & distributions  # never the dev tools
    pyhanko = next(c for c in bom["components"] if c["name"] == "pyhanko")
    assert pyhanko["version"] == "0.25.1"
    assert pyhanko["licenses"]  # every Python component says its licence
    fonts = [c for c in bom["components"] if c["type"] == "file"]
    assert {c["name"] for c in fonts} == {"Arvo", "Source Sans 3"}


def test_extras_and_other_platforms_are_left_out() -> None:
    sbom = _script("sbom.py")
    needs = sbom._needs(
        ["a>=1", "b; extra == 'docs'", "c; python_version < '3'", "D_E; sys_platform != 'x'"]
    )
    assert needs == ["a", "d-e"]


def test_a_measure_much_slower_than_the_reference_is_warned() -> None:
    rendimiento = _script("rendimiento.py")
    reference = {"segundos": {}, "relativo": {"firmar": 2.0, "verificar": 1.0}}
    same = {"segundos": {}, "relativo": {"firmar": 2.9, "verificar": 1.0}}
    assert rendimiento.compare(same, reference) == []  # 45 % slower: noise
    slower = {"segundos": {}, "relativo": {"firmar": 2.0, "verificar": 1.6, "nueva": 9.0}}
    assert rendimiento.compare(slower, reference) == [
        "verificar: 1.60 veces el tiempo de referencia"
    ]


def test_debsecan_entries_of_other_packages_are_left_out() -> None:
    debian = _script("vulnerabilidades-debian.py")
    report = """CVE-2026-0001
  Use after free in libxml2 ...
  installed: libxml2 2.9.14-2.1+deb13u3
             (built from libxml2 2.9.14-2.1+deb13u3)
  fixed in unstable: libxml2 2.15.4+dfsg-1 (source package)

CVE-2026-0002
  A flaw in cryptography ...
  installed: python3-cryptography 43.0.0-3+deb13u1
             (built from python-cryptography 43.0.0-3+deb13u1)

TEMP-0000001-ABCDEF
  An issue in lxml ...
  installed: python3-lxml 5.4.0-1
             (built from lxml 5.4.0-1)
  fixed in trixie-security: lxml 5.4.0-1+deb13u1 (source package)
"""
    assert debian.parse(report, {"python3-cryptography", "python3-lxml"}) == [
        ("CVE-2026-0002", "python3-cryptography", "A flaw in cryptography ...", "sin corrección"),
        (
            "TEMP-0000001-ABCDEF",
            "python3-lxml",
            "An issue in lxml ...",
            "trixie-security: lxml 5.4.0-1+deb13u1",
        ),
    ]


def test_the_c_libraries_under_the_python_packages_are_included() -> None:
    """libxml2 parses the XML berigna opens: it comes in through python3-lxml (review)."""
    debian = _script("vulnerabilidades-debian.py")
    graph = {"python3-lxml": {"libxml2", "libc6"}, "libxml2": {"libc6", "zlib1g"}}
    assert debian.closure({"python3-lxml"}, lambda p: graph.get(p, set())) == {
        "python3-lxml",
        "libxml2",
        "libc6",
        "zlib1g",
    }


def test_the_environment_has_the_declared_dependency_versions() -> None:
    """DP-19, R-DES-16: the CI's environment has what pyproject.toml declares."""
    assert _script("verificar-dependencias.py").main() == 0


def test_a_dependency_out_of_bounds_or_missing_is_named() -> None:
    dependencias = _script("verificar-dependencias.py")
    found = dependencias.problems(
        ["pyhanko-certvalidator~=0.30.0", "packaging>=1", "berigna-no-existe>=1"]
    )
    assert len(found) == 2
    assert found[0].startswith("pyhanko-certvalidator 0.26.")
    assert "fuera de los límites" in found[0]
    assert found[1].startswith("berigna-no-existe: no está instalado")
