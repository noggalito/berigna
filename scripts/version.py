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
import time
from dataclasses import dataclass
from pathlib import Path

from packaging.version import Version as Pep440

ROOT = Path(__file__).resolve().parents[1]
MAINTAINER = "noggalito <berigna@noggalito.com>"
DISTRIBUTION = "trixie"
UNRELEASED = "## [Sin publicar]"
_N = r"(0|[1-9]\d*)"  # SemVer: no leading zeros
_SEMVER = re.compile(rf"{_N}\.{_N}\.{_N}(?:-(alpha|beta|rc)\.{_N})?")
_PEP440_PRE = {"alpha": "a", "beta": "b", "rc": "rc"}


class VersionError(Exception):
    """The version, or the state of the repository, does not allow the step."""


@dataclass(frozen=True)
class Version:
    semver: str  # 1.0.0-rc.2: the tag (with a "v") and the CHANGELOG
    pep440: str  # 1.0.0rc2: pyproject.toml, meson.build, __version__
    debian: str  # 1.0.0~rc2: upstream version of the Debian package (sorts before 1.0.0)

    @property
    def appstream(self) -> str:
        """The metainfo's form: AppStream, like Debian, sorts "1.0.0~rc.2" before "1.0.0",
        and "1.0.0-rc.2" after it (appstreamcli: releases-not-in-order)."""
        return self.semver.replace("-", "~", 1)

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
    current = _released(root)
    if current is not None and Pep440(version.pep440) <= current:
        raise VersionError(f"{version.semver} no es posterior a la versión actual ({current})")
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
        r"^([ \t]*)<releases>\n",
        rf'\1<releases>\n\1  <release version="{version.appstream}" date="{day.isoformat()}"/>\n',
        metainfo,
    )
    debian = (root / "debian/changelog").read_text(encoding="utf-8")
    updates["debian/changelog"] = _debian_entry(version, when) + debian
    for name, content in updates.items():  # only once every place was found
        (root / name).write_text(content, encoding="utf-8")


def _released(root: Path) -> Pep440 | None:
    """The newest version the repository already carries: pyproject.toml, or the first
    <release> of the metainfo (v0.3.0-rc.1 was tagged by hand, ahead of pyproject)."""
    found = []
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    line = re.search(r'^version = "([^"]*)"', text, re.MULTILINE)
    if line:
        found.append(Pep440(line.group(1)))
    metainfo = (root / "data/com.noggalito.Berigna.metainfo.xml.in").read_text(encoding="utf-8")
    release = re.search(r'<release version="([^"]*)"', metainfo)
    if release:
        found.append(Pep440(parse(release.group(1).replace("~", "-", 1)).pep440))
    return max(found) if found else None


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
    if first is None or first.group(1) != version.appstream:
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
    if _git("tag", "--list", version.tag) or _git(
        "ls-remote", "--tags", "origin", f"refs/tags/{version.tag}"
    ):
        raise VersionError(f"la etiqueta {version.tag} ya existe, aquí o en origin")
    found = problems(ROOT, version)
    if found:
        raise VersionError("la versión no está preparada:\n  " + "\n  ".join(found))


PACKAGES = ("berigna", "berigna-nautilus")


def built_packages(build: Path, version: Version, since: float) -> list[Path]:
    """The .deb of each package of ``version`` built after ``since`` (a time stamp) under
    ``build``: debuild leaves them in build/, debcraft in a folder of its own for each
    build. Both packages must be there: an older copy of the same version is never taken."""
    newest: dict[str, Path] = {}
    for deb in build.rglob(f"*_{version.package}_all.deb"):
        if "version" in deb.relative_to(build).parts[:1] or deb.stat().st_mtime < since:
            continue  # the copies of an earlier run of this script, or an earlier build
        if deb.name not in newest or deb.stat().st_mtime > newest[deb.name].stat().st_mtime:
            newest[deb.name] = deb
    missing = [p for p in PACKAGES if f"{p}_{version.package}_all.deb" not in newest]
    if missing:
        raise VersionError(f"no se construyeron: {', '.join(missing)}")
    return [newest[f"{p}_{version.package}_all.deb"] for p in PACKAGES]


def tag(version: Version, builder: str) -> Path:
    """verificar.sh, the packages and their SHA-256, the notes and the signed tag; returns
    the folder with the packages and the notes."""
    _check_repository(version)
    _run("scripts/verificar.sh")
    start = time.time() - 1  # file times may be rounded down
    _run("scripts/empaquetar-berigna.sh", builder, "comprobar")
    debs = built_packages(ROOT / "build", version, start)
    out = ROOT / "build" / "version" / version.tag
    out.mkdir(parents=True, exist_ok=True)
    sums = []
    for deb in debs:
        data = deb.read_bytes()
        (out / deb.name).write_bytes(data)
        sums.append((deb.name, hashlib.sha256(data).hexdigest()))
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
    # verbatim: git's default cleanup drops the lines that start with "#", the headings
    message = f"berigna {version.semver}\n\n{body}\n"
    _run("git", "tag", "-s", "--cleanup=verbatim", version.tag, "-m", message)
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
            now = dt.datetime.now().astimezone()  # debian/changelog: the same day as the rest
            prepare(ROOT, version, args.fecha, dt.datetime.combine(args.fecha, now.timetz()))
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
