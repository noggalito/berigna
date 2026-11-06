#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Builds the berigna package against Debian 13 (BRG-DSP-001, Fase 5 incremento 3):
# exports the git tree as the upstream tarball of the source format 3.0 (quilt)
# (debian/ excluded, as the format requires), adds debian/ and builds reproducibly
# with debcraft (in ephemeral containers) or debuild.
# Needs git and tar, and for the builders: debcraft (with Podman or Docker) or devscripts.
#
#   scripts/empaquetar-berigna.sh [debcraft|debuild] [comprobar]
#
# "comprobar" runs lintian --pedantic over the built package. piuparts needs root and a
# base image of trixie (for instance debian-13-genericcloud-amd64.tar.xz from
# https://cdimage.debian.org/images/cloud/trixie/): in the Debian 13 VM,
#   sudo piuparts -d trixie -b /var/cache/piuparts/base.tar.xz build/berigna_0.1.0~dev0-1_all.deb
set -eu
cd "$(git rev-parse --show-toplevel)"

# The upstream version of debian/changelog (meson.build carries 0.1.0.dev0, the
# Debian form of the same version, see PEP 440).
VERSION=$(dpkg-parsechangelog -S Version -c1 | sed 's/-[^-]*$//')
BUILDER=${1:-debcraft}
CHECK=${2:-}

mkdir -p build
TARBALL="build/berigna_${VERSION}.orig.tar.gz"
# The source format 3.0 (quilt) needs the upstream tarball under its Debian name,
# next to the unpacked tree; debian/ lives in the repository and is added below,
# as the format requires (it belongs to the Debian tarball, not to the orig).
git archive --format=tar.gz --prefix="berigna-$VERSION/" -o "$TARBALL" HEAD -- . ':!debian'

SRC="build/berigna-$VERSION"
rm -rf "$SRC"
tar xzf "$TARBALL" -C build
cp -r debian "$SRC/debian"

cd "$SRC"
# Reproducible: the timestamp of the packaging in this repository.
export SOURCE_DATE_EPOCH=$(git -C "$OLDPWD" log -1 --format=%ct -- debian)
case "$BUILDER" in
    # --skip-sources: only the .deb, no source package (the 3.0 (quilt) orig tarball is
    # not visible inside the build container); debuild below does produce it.
    debcraft) debcraft build --skip-sources ;;
    debuild) dpkg-buildpackage -us -uc ;;
    *) echo "uso: $0 [debcraft|debuild] [comprobar]" >&2; exit 2 ;;
esac
cd - >/dev/null

DEB=$(find build -name 'berigna_*.deb' -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
[ -n "$DEB" ] || { echo "no se encontró el .deb" >&2; exit 1; }
echo "paquete: $DEB"

if [ "$CHECK" = comprobar ]; then
    lintian --pedantic "$DEB"
    echo "piuparts (en la VM, con root):"
    echo "  sudo piuparts -d trixie -b /var/cache/piuparts/base.tar.xz $DEB"
fi
