#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Builds the three .deb of the project (python3-pyhanko, berigna, berigna-nautilus) with
# debuild and leaves them in build/paquetes/ with their SHA256SUMS: the single deliverable
# of the Debian family (ADR-0023), which the CI and the weekly watch install on each
# distribution. Runs as root in a debian:trixie container, with the full git history (the
# packaging scripts take SOURCE_DATE_EPOCH from it).
#
#   podman run --rm -v "$PWD:/src:ro" debian:trixie sh -c \
#       'apt-get update && apt-get install -y git && git clone /src /tmp/b && cd /tmp/b &&
#        scripts/compilar-paquetes.sh'
set -eu
cd "$(dirname "$0")/.."

echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates git curl dpkg-dev
DEBIAN_FRONTEND=noninteractive apt-get build-dep -y ./ ./packaging/python3-pyhanko

git config --global --add safe.directory "$PWD"
scripts/empaquetar-pyhanko.sh debuild
scripts/empaquetar-berigna.sh debuild
rm -rf build/paquetes
mkdir -p build/paquetes
cp build/*.deb build/paquetes/
cd build/paquetes && sha256sum ./*.deb | tee SHA256SUMS
