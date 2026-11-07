#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Builds python3-pyhanko 0.25.1 against Debian 13 (DP-06, ADR-0013; SPK-05):
# downloads the pinned sdist, verifies its SHA-256, adds packaging/python3-pyhanko/debian
# and builds reproducibly with debcraft (in ephemeral containers) or debuild.
# Needs curl, and for the builders: debcraft (with Podman or Docker) or devscripts.
#
#   scripts/empaquetar-pyhanko.sh [debcraft|debuild] [comprobar]
#
# "comprobar" runs lintian --pedantic over the built package. piuparts needs root; without
# -b it builds the chroot with debootstrap from the network, and -s saves it as a base to
# reuse with -b:
#   sudo piuparts -d trixie -s /var/cache/piuparts/base.tar.xz build/pyhanko_0.25.1-1_all.deb
set -eu
cd "$(git rev-parse --show-toplevel)"

VERSION=0.25.1
SHA256=8718d9046d442589eef6dd6973110fa5e385555cc4a6b2b1aeca3c2f3b6742e9
URL="https://files.pythonhosted.org/packages/99/59/d165478e7cef237cb7d22ac80e062829fcb13736c3edc71e5f7a1e814163/pyhanko-$VERSION.tar.gz"
BUILDER=${1:-debcraft}
CHECK=${2:-}

mkdir -p build
TARBALL="build/pyhanko-$VERSION.tar.gz"
[ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "$URL"
echo "$SHA256  $TARBALL" | sha256sum -c -
# The source format 3.0 (quilt) needs the upstream tarball under its Debian name,
# next to the unpacked tree.
cp "$TARBALL" "build/pyhanko_${VERSION}.orig.tar.gz"

SRC="build/pyhanko-$VERSION"
rm -rf "$SRC"
tar xzf "$TARBALL" -C build
cp -r packaging/python3-pyhanko/debian "$SRC/debian"

cd "$SRC"
# Reproducible: the timestamp of the packaging in this repository.
export SOURCE_DATE_EPOCH=$(git -C "$OLDPWD" log -1 --format=%ct -- packaging/python3-pyhanko)
case "$BUILDER" in
    # --skip-sources: only the .deb, no source package (the 3.0 (quilt) orig tarball is
    # not visible inside the build container); debuild below does produce it.
    debcraft) debcraft build --skip-sources ;;
    debuild) dpkg-buildpackage -us -uc ;;
    *) echo "uso: $0 [debcraft|debuild] [comprobar]" >&2; exit 2 ;;
esac
cd - >/dev/null

DEB=$(find build -name 'python3-pyhanko_*.deb' -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
[ -n "$DEB" ] || { echo "no se encontró el .deb" >&2; exit 1; }
echo "paquete: $DEB"

if [ "$CHECK" = comprobar ]; then
    lintian --pedantic "$DEB"
    echo "piuparts (en la VM, con root):"
    echo "  sudo piuparts -d trixie -b /var/cache/piuparts/base.tar.xz $DEB"
fi
