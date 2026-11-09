#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Builds the .deb of the project (python3-pyhanko, berigna, berigna-nautilus and
# noggalito-archive-keyring) with debuild and leaves them in build/paquetes/ with their SHA256SUMS: the single deliverable
# of the Debian family (ADR-0023), which the CI and the weekly watch install on each
# distribution. Runs as root in a debian:trixie container, with the full git history (the
# packaging scripts take SOURCE_DATE_EPOCH from it).
#
#   podman run --rm -v "$PWD:/src:ro" debian:trixie sh -c \
#       'apt-get update && apt-get install -y git && git clone /src /tmp/b && cd /tmp/b &&
#        scripts/compilar-paquetes.sh'
set -eu
cd "$(dirname "$0")/.."

# Like probar-paquete-instalado.sh: it changes apt and deletes the .deb of earlier builds.
if [ ! -e /run/.containerenv ] && [ ! -e /.dockerenv ] && [ -z "${GITHUB_ACTIONS:-}" ]; then
  echo "solo dentro de un contenedor: instala las dependencias de compilación" >&2
  exit 2
fi

echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates git curl dpkg-dev
DEBIAN_FRONTEND=noninteractive apt-get build-dep -y ./ ./packaging/python3-pyhanko \
  ./packaging/noggalito-archive-keyring

git config --global --add safe.directory "$PWD"
# Only what this run builds: an older .deb in build/ would travel with the new ones.
rm -f build/*.deb
scripts/empaquetar-pyhanko.sh debuild
scripts/empaquetar-berigna.sh debuild
# The key and source of the repository (DP-24): a native package, built in a copy so that
# packaging/ stays clean; the .deb lands in build/.
rm -rf build/noggalito-archive-keyring
cp -r packaging/noggalito-archive-keyring build/
(cd build/noggalito-archive-keyring &&
  SOURCE_DATE_EPOCH=$(git log -1 --format=%ct -- ../../packaging/noggalito-archive-keyring) \
  dpkg-buildpackage -b -us -uc >/dev/null)
rm -rf build/paquetes
mkdir -p build/paquetes
cp build/*.deb build/paquetes/
cd build/paquetes && sha256sum ./*.deb | tee SHA256SUMS
