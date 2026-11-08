# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The development scripts of the increment 7 of Phase 4: the SBOM (R-DES-03) and the
performance comparison (R-DES-10)."""

import datetime as dt
import importlib.util
import os
import tomllib
from pathlib import Path
from types import ModuleType

import pytest
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


def test_each_bound_becomes_a_debian_relation() -> None:
    """ADR-0023: apt must refuse what pip would refuse."""
    relations = _script("verificar-dependencias.py").debian_relations
    assert relations("cryptography>=42") == ("python3-cryptography", {(">=", "42")})
    assert relations("pyhanko-certvalidator~=0.26.3")[1] == {(">=", "0.26.3"), ("<<", "0.27~")}
    assert relations("asn1crypto~=1.5")[1] == {(">=", "1.5"), ("<<", "2~")}
    assert relations("pyhanko==0.25.1")[1] == {(">=", "0.25.1"), ("<<", "0.25.2~")}
    assert relations("signxml~=4.0.post1")[1] == {(">=", "4.0.post1"), ("<<", "5~")}
    assert relations("Pillow>=10")[0] == "python3-pil"
    assert relations("typing_extensions>=4")[0] == "python3-typing-extensions"
    for unsupported in ("lxml!=5.1", "pyhanko==0.25.*", "lxml<6"):
        with pytest.raises(ValueError, match="sin equivalente"):
            relations(unsupported)


def test_a_bound_missing_from_debian_control_is_named() -> None:
    dependencias = _script("verificar-dependencias.py")
    control = (
        "Source: berigna\n\nPackage: berigna\n# a comment\nDepends: ${misc:Depends},\n"
        " python3-cryptography:any (>= 41),\n python3-signxml (>= 4.0),\n"
        " python3-signxml (<< 5~),\n python3-pil (>= 10) | python3-pillow\n"
        "Description: x\n\nPackage: otro\nDepends: python3-lxml\n"
    )
    found = dependencias.control_problems(
        ["cryptography>=42", "signxml~=4.0", "lxml>=5", "pillow>=10", "x==1.*"], control
    )
    assert found == [
        "debian/control: python3-cryptography debe llevar (>= 42) (cryptography>=42)",
        "debian/control: falta python3-lxml en el Depends de berigna (lxml>=5)",
        "pyproject.toml: x==1.*: sin equivalente en Debian (==1.*)",
    ]


_RELEASE_FILES = {
    "pyproject.toml": '[project]\nname = "berigna"\nversion = "0.1.0.dev0"\n',
    "meson.build": "project(\n  'berigna',\n  version: '0.1.0.dev0',\n)\n",
    "src/berigna/__init__.py": '"""berigna."""\n\n__version__ = "0.1.0.dev0"\n',
    "debian/changelog": (
        "berigna (0.1.0~dev0-1) trixie; urgency=medium\n\n  * Initial package.\n\n"
        " -- noggalito <berigna@noggalito.com>  Thu, 05 Nov 2026 12:00:00 -0500\n"
    ),
    # a blank line before <releases>: the new release keeps the indentation
    "data/com.noggalito.Berigna.metainfo.xml.in": (
        '<component>\n\n  <releases>\n    <release version="0.3.0~rc.1" date="2026-10-29"/>\n'
        "  </releases>\n</component>\n"
    ),
    "CHANGELOG.md": (
        "# Registro de cambios\n\n## [Sin publicar]\n\n### Añadido\n\n- Algo nuevo.\n\n"
        "### Corregido\n\n- Un fallo.\n"
    ),
}


def _release_tree(tmp_path: Path) -> Path:
    """Files of their own, not the repository's: preparing a real version empties its
    "Sin publicar" and must not break this test."""
    for name, content in _RELEASE_FILES.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


def test_a_version_is_written_in_each_form() -> None:
    """R-DES-09: SemVer in the tag, PEP 440 for Python and Meson, ~ for Debian."""
    version = _script("version.py")
    rc = version.parse("v1.0.0-rc.2")
    assert (rc.semver, rc.pep440, rc.debian, rc.package, rc.tag) == (
        "1.0.0-rc.2",
        "1.0.0rc2",
        "1.0.0~rc2",
        "1.0.0~rc2-1",
        "v1.0.0-rc.2",
    )
    final = version.parse("1.0.0")
    assert (final.pep440, final.debian) == ("1.0.0", "1.0.0")
    # AppStream sorts "1.0.0-rc.2" after "1.0.0" (appstreamcli: releases-not-in-order)
    assert (rc.appstream, final.appstream) == ("1.0.0~rc.2", "1.0.0")
    assert version.parse("0.4.0-beta.1").pep440 == "0.4.0b1"
    for wrong in ("1.0", "1.0.0-rc2", "1.0.0.dev0", "1.0.0-rc.2+x", "01.0.0", "1.0.0-rc.01"):
        with pytest.raises(version.VersionError):
            version.parse(wrong)


def test_preparing_a_version_updates_the_six_places(tmp_path: Path) -> None:
    version = _script("version.py")
    root = _release_tree(tmp_path)
    target = version.parse("0.3.0-rc.2")
    assert version.problems(root, target)  # the files are not at that version
    when = dt.datetime(2026, 11, 8, 10, 30, tzinfo=dt.timezone(dt.timedelta(hours=-5)))
    version.prepare(root, target, when.date(), when)
    assert version.problems(root, target) == []
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [Sin publicar]\n\n## [0.3.0-rc.2] - 2026-11-08\n\n### Añadido\n" in changelog
    assert (
        version.notes(root, target)
        == "### Añadido\n\n- Algo nuevo.\n\n### Corregido\n\n- Un fallo."
    )
    debian = (root / "debian/changelog").read_text(encoding="utf-8")
    assert debian.startswith("berigna (0.3.0~rc2-1) trixie; urgency=medium\n")
    assert " -- noggalito <berigna@noggalito.com>  Sun, 08 Nov 2026 10:30:00 -0500\n" in debian
    assert debian.endswith(_RELEASE_FILES["debian/changelog"])
    metainfo = (root / "data/com.noggalito.Berigna.metainfo.xml.in").read_text(encoding="utf-8")
    assert '\n  <releases>\n    <release version="0.3.0~rc.2" date="2026-11-08"/>\n' in metainfo
    # the same version again: refused, nothing changes
    with pytest.raises(version.VersionError, match="ya tiene"):
        version.prepare(root, target, when.date(), when)
    # the new "Sin publicar" is empty: the next version needs something to announce
    with pytest.raises(version.VersionError, match="vacía"):
        version.prepare(root, version.parse("0.3.0"), when.date(), when)
    assert version.problems(root, target) == []


def test_a_version_older_than_the_current_one_is_refused(tmp_path: Path) -> None:
    """The metainfo already lists 0.3.0-rc.1, ahead of pyproject.toml (tagged by hand)."""
    version = _script("version.py")
    root = _release_tree(tmp_path)
    day = dt.date(2026, 11, 8)
    when = dt.datetime(2026, 11, 8, 10, 30, tzinfo=dt.UTC)
    for older in ("0.2.0", "0.3.0-rc.1", "0.3.0-beta.4"):
        with pytest.raises(version.VersionError, match="no es posterior"):
            version.prepare(root, version.parse(older), day, when)
    assert (root / "CHANGELOG.md").read_text(encoding="utf-8") == _RELEASE_FILES["CHANGELOG.md"]


def test_the_packages_of_the_version_are_those_of_this_build(tmp_path: Path) -> None:
    """debuild leaves the .deb in build/, debcraft in a folder for each build. Only those
    built after the start count (not an older build of the same version, nor the copies of
    an earlier run), and both packages must be there."""
    version = _script("version.py")
    target = version.parse("0.3.0-rc.2")
    old = tmp_path / "debcraft-build-berigna-1" / "berigna_0.3.0~rc2-1_all.deb"
    old_nautilus = tmp_path / "debcraft-build-berigna-1" / "berigna-nautilus_0.3.0~rc2-1_all.deb"
    new = tmp_path / "debcraft-build-berigna-2" / "berigna_0.3.0~rc2-1_all.deb"
    nautilus = tmp_path / "debcraft-build-berigna-2" / "berigna-nautilus_0.3.0~rc2-1_all.deb"
    copy = tmp_path / "version" / "v0.3.0-rc.2" / "berigna_0.3.0~rc2-1_all.deb"
    other = tmp_path / "berigna_0.1.0~dev0-1_all.deb"
    times = {
        old: 1_000,
        old_nautilus: 1_000,
        new: 2_000,
        nautilus: 2_000,
        copy: 3_000,
        other: 2_000,
    }
    for path, moment in times.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"deb")
        os.utime(path, (moment, moment))
    assert version.built_packages(tmp_path, target, 1_500) == [new, nautilus]
    nautilus.unlink()  # this build did not produce it: the older one is not taken instead
    with pytest.raises(version.VersionError, match="berigna-nautilus"):
        version.built_packages(tmp_path, target, 1_500)


def test_the_dependencies_built_with_the_version_are_found(tmp_path: Path) -> None:
    """python3-pyhanko goes with every version: berigna depends on it and Debian 13 does not
    have it. The newest built after the start, not an older one nor an earlier copy."""
    version = _script("version.py")
    old = tmp_path / "python3-pyhanko_0.25.1-1_all.deb"
    new = tmp_path / "debcraft-build-pyhanko-2" / "python3-pyhanko_0.25.1-1_all.deb"
    copy = tmp_path / "version" / "v0.3.0" / "python3-pyhanko_0.25.1-1_all.deb"
    for path, moment in ((old, 1_000), (new, 2_000), (copy, 3_000)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"deb")
        os.utime(path, (moment, moment))
    assert version.built_dependency(tmp_path, "python3-pyhanko", 1_500) == new
    with pytest.raises(version.VersionError, match="python3-pyhanko"):
        version.built_dependency(tmp_path, "python3-pyhanko", 2_500)


def test_the_release_notes_say_how_to_install(tmp_path: Path) -> None:
    version = _script("version.py")
    notes = version.release_notes(
        version.parse("0.3.0"),
        "### Añadido\n\n- Algo.",
        [("berigna_0.3.0-1_all.deb", "aa"), ("python3-pyhanko_0.25.1-1_all.deb", "bb")],
        ["berigna_0.3.0-1_all.deb", "python3-pyhanko_0.25.1-1_all.deb"],
        "berigna-nautilus_0.3.0-1_all.deb",
    )
    assert notes.startswith("# berigna 0.3.0\n\n### Añadido\n\n- Algo.\n\n## Instalación")
    assert (
        "sudo apt install ./berigna_0.3.0-1_all.deb ./python3-pyhanko_0.25.1-1_all.deb\n" in notes
    )
    assert "`sudo apt install ./berigna-nautilus_0.3.0-1_all.deb`" in notes
    assert "- `python3-pyhanko_0.25.1-1_all.deb`, SHA-256 `bb`" in notes
