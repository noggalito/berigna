#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""The release process of berigna (R-DES-09; BRG-DES-001 §6).

A version is written as SemVer, as in the tag (``1.0.0``, ``1.0.0-rc.2``), and appears in
six places, each in its own form: pyproject.toml, meson.build and berigna/__init__.py
(PEP 440: ``1.0.0rc2``), debian/changelog (``1.0.0~rc2-1``), the AppStream metainfo and the
CHANGELOG (SemVer).

    scripts/version.py preparar VERSIÓN [--fecha AAAA-MM-DD]
        writes the version in the six places; the CHANGELOG's "Sin publicar" becomes the
        section of the version. The change goes to main through a PR, like any other.
    scripts/version.py comprobar VERSIÓN
        the six places carry VERSIÓN.
    scripts/version.py etiquetar VERSIÓN [--constructor debcraft|debuild]
        on main, clean and equal to origin/main: verificar.sh, the .deb packages (berigna and
        berigna-nautilus), their SHA-256, the
        notes from the CHANGELOG and the signed tag (git tag -s, the SSH key of the commits),
        all in build/version/vVERSIÓN/. Pushing the tag and the release on GitHub are left to
        the person, who sees the commands at the end: nothing leaves the machine by itself.
"""

import argparse
import datetime as dt
import email.utils
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAINTAINER = "noggalito <berigna@noggalito.com>"
DISTRIBUTION = "trixie"
UNRELEASED = "## [Sin publicar]"
_SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?")
_PEP440_PRE = {"alpha": "a", "beta": "b", "rc": "rc"}


class VersionError(Exception):
    """The version, or the state of the repository, does not allow the step."""


@dataclass(frozen=True)
class Version:
    semver: str  # 1.0.0-rc.2: the tag (with a "v"), the metainfo, the CHANGELOG
    pep440: str  # 1.0.0rc2: pyproject.toml, meson.build, __version__
    debian: str  # 1.0.0~rc2: upstream version of the Debian package (sorts before 1.0.0)

    @property
    def tag(self) -> str:
        return f"v{self.semver}"

    @property
    def package(self) -> str:
        """The Debian version of the package: revision 1 of the upstream version."""
        return f"{self.debian}-1"


def parse(text: str) -> Version:
    match = _SEMVER.fullmatch(text.removeprefix("v"))
    if match is None:
        raise VersionError(f"versión no válida: {text!r} (se espera 1.0.0 o 1.0.0-rc.2)")
    major, minor, patch, kind, number = match.groups()
    base = f"{major}.{minor}.{patch}"
    if kind is None:
        return Version(base, base, base)
    return Version(
        f"{base}-{kind}.{number}", f"{base}{_PEP440_PRE[kind]}{number}", f"{base}~{kind}{number}"
    )


# -- the six places -------------------------------------------------------------------------


def _replace_once(text: str, pattern: str, replacement: str, where: str) -> str:
    new, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise VersionError(f"no se encontró la versión en {where}")
    return new


def _simple_places(version: Version) -> list[tuple[str, str, str]]:
    """(file, pattern, replacement) of the places with a single version line."""
    return [
        ("pyproject.toml", r'^version = "[^"]*"', f'version = "{version.pep440}"'),
        ("meson.build", r"^  version: '[^']*',", f"  version: '{version.pep440}',"),
        ("src/berigna/__init__.py", r'^__version__ = "[^"]*"', f'__version__ = "{version.pep440}"'),
    ]


def _debian_entry(version: Version, when: dt.datetime) -> str:
    return (
        f"berigna ({version.package}) {DISTRIBUTION}; urgency=medium\n\n"
        f"  * Upstream release {version.semver} (CHANGELOG.md).\n\n"
        f" -- {MAINTAINER}  {email.utils.format_datetime(when)}\n\n"
    )


def prepare(root: Path, version: Version, day: dt.date, when: dt.datetime) -> None:
    """Write ``version`` in the six places (released on ``day``; ``when`` for Debian)."""
    changelog = root / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")
    if f"## [{version.semver}]" in text:
        raise VersionError(f"el CHANGELOG ya tiene la sección {version.semver}")
    if UNRELEASED not in text:
        raise VersionError(f"el CHANGELOG no tiene la sección {UNRELEASED!r}")
    head, _, rest = text.partition(UNRELEASED)
    if not rest.split("\n## [", 1)[0].strip():
        raise VersionError("la sección «Sin publicar» del CHANGELOG está vacía")
    updates = {
        "CHANGELOG.md": f"{head}{UNRELEASED}\n\n## [{version.semver}] - {day.isoformat()}{rest}"
    }
    for name, pattern, replacement in _simple_places(version):
        updates[name] = _replace_once(
            (root / name).read_text(encoding="utf-8"), pattern, replacement, name
        )
    metainfo = "data/com.noggalito.Berigna.metainfo.xml.in"
    updates[metainfo] = _replace_once(
        (root / metainfo).read_text(encoding="utf-8"),
        r"^(\s*)<releases>\n",
        rf'\1<releases>\n\1  <release version="{version.semver}" date="{day.isoformat()}"/>\n',
        metainfo,
    )
    debian = (root / "debian/changelog").read_text(encoding="utf-8")
    updates["debian/changelog"] = _debian_entry(version, when) + debian
    for name, content in updates.items():  # only once every place was found
        (root / name).write_text(content, encoding="utf-8")


def problems(root: Path, version: Version) -> list[str]:
    """What does not carry ``version`` among the six places."""
    found = []
    for name, pattern, replacement in _simple_places(version):
        line = re.search(pattern, (root / name).read_text(encoding="utf-8"), re.MULTILINE)
        if line is None or line.group(0) != replacement:
            found.append(f"{name}: {line.group(0) if line else 'sin versión'}")
    debian = (root / "debian/changelog").read_text(encoding="utf-8").split("\n", 1)[0]
    if not debian.startswith(f"berigna ({version.package}) "):
        found.append(f"debian/changelog: {debian}")
    metainfo = (root / "data/com.noggalito.Berigna.metainfo.xml.in").read_text(encoding="utf-8")
    first = re.search(r'<release version="([^"]*)"', metainfo)
    if first is None or first.group(1) != version.semver:
        found.append(f"metainfo: {first.group(1) if first else 'sin <release>'}")
    if notes(root, version) is None:
        found.append(f"CHANGELOG.md: sin la sección [{version.semver}]")
    return found


def notes(root: Path, version: Version) -> str | None:
    """The CHANGELOG section of ``version``, without its heading."""
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        rf"^## \[{re.escape(version.semver)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S
    )
    return match.group(1).strip() if match else None


# -- the tag and the package -----------------------------------------------------------------


def _run(*command: str) -> None:
    """A program of the repository or of the system, with fixed arguments; stops on failure."""
    subprocess.run(command, cwd=ROOT, check=True)  # noqa: S603 - fixed programs and arguments


def _git(*args: str) -> str:
    result = subprocess.run(  # noqa: S603 - git with fixed arguments
        ["git", *args],  # noqa: S607 - git from PATH, like the other scripts
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _check_repository(version: Version) -> None:
    if _git("rev-parse", "--abbrev-ref", "HEAD") != "main":
        raise VersionError("las versiones se etiquetan en main")
    if _git("status", "--porcelain"):
        raise VersionError("el árbol de trabajo no está limpio")
    _git("fetch", "--quiet", "origin", "main")
    if _git("rev-parse", "HEAD") != _git("rev-parse", "origin/main"):
        raise VersionError("main no coincide con origin/main (git pull --ff-only)")
    if _git("tag", "--list", version.tag):
        raise VersionError(f"la etiqueta {version.tag} ya existe")
    found = problems(ROOT, version)
    if found:
        raise VersionError("la versión no está preparada:\n  " + "\n  ".join(found))


def built_packages(build: Path, version: Version) -> list[Path]:
    """The newest .deb of each package of ``version`` under ``build``: debuild leaves them in
    build/, debcraft in a folder of its own for each build (berigna and berigna-nautilus)."""
    newest: dict[str, Path] = {}
    for deb in build.rglob(f"*_{version.package}_all.deb"):
        if "version" in deb.relative_to(build).parts[:1]:
            continue  # the copies of an earlier run of this script
        if deb.name not in newest or deb.stat().st_mtime > newest[deb.name].stat().st_mtime:
            newest[deb.name] = deb
    return [newest[name] for name in sorted(newest)]


def tag(version: Version, builder: str) -> Path:
    """verificar.sh, the packages and their SHA-256, the notes and the signed tag; returns
    the folder with the packages and the notes."""
    _check_repository(version)
    _run("scripts/verificar.sh")
    _run("scripts/empaquetar-berigna.sh", builder, "comprobar")
    debs = built_packages(ROOT / "build", version)
    if not any(deb.name.startswith("berigna_") for deb in debs):
        raise VersionError(f"no se construyó berigna_{version.package}_all.deb")
    out = ROOT / "build" / "version" / version.tag
    out.mkdir(parents=True, exist_ok=True)
    sums = []
    for deb in debs:
        (out / deb.name).write_bytes(deb.read_bytes())
        sums.append((deb.name, hashlib.sha256(deb.read_bytes()).hexdigest()))
    (out / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sums), encoding="utf-8"
    )
    body = notes(ROOT, version) or ""
    packages = "".join(f"- `{name}`, SHA-256 `{digest}`\n" for name, digest in sums)
    text = (
        f"# berigna {version.semver}\n\n{body}\n\n## Paquetes\n\n{packages}\n"
        "Versión no acreditada ante INDECOPI. Las evidencias de las pruebas de esta versión "
        "están en BRG-CAL-001 §9.\n"
    )
    (out / "notas.md").write_text(text, encoding="utf-8")
    _run("git", "tag", "-s", version.tag, "-m", f"berigna {version.semver}\n\n{body}")
    _run("git", "tag", "-v", version.tag)  # the signature verifies with the allowed keys
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Proceso de versión de berigna (R-DES-09)")
    steps = parser.add_subparsers(dest="paso", required=True)
    prepare_step = steps.add_parser("preparar")
    prepare_step.add_argument("version")
    prepare_step.add_argument("--fecha", type=dt.date.fromisoformat, default=dt.date.today())
    steps.add_parser("comprobar").add_argument("version")
    tag_step = steps.add_parser("etiquetar")
    tag_step.add_argument("version")
    tag_step.add_argument("--constructor", choices=["debcraft", "debuild"], default="debcraft")
    args = parser.parse_args(argv)
    try:
        version = parse(args.version)
        if args.paso == "preparar":
            prepare(ROOT, version, args.fecha, dt.datetime.now().astimezone())
            print(f"versión {version.semver} escrita; revisa el diff y llévala a main en un PR")
        elif args.paso == "comprobar":
            found = problems(ROOT, version)
            for problem in found:
                print(f"version.py: {problem}", file=sys.stderr)
            return 1 if found else 0
        else:
            out = tag(version, args.constructor)
            print(f"\npaquete y notas en {out.relative_to(ROOT)}/; para publicar:")
            print(f"  git push origin {version.tag}")
            print(
                f"  gh release create {version.tag} {out.relative_to(ROOT)}/*.deb "
                f"{out.relative_to(ROOT)}/SHA256SUMS --notes-file {out.relative_to(ROOT)}/notas.md"
                + (" --prerelease" if "-" in version.semver else "")
            )
    except VersionError as exc:
        print(f"version.py: {exc}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:  # its output is already on the terminal
        print(f"version.py: falló {' '.join(map(str, exc.cmd))}; no se etiquetó", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
