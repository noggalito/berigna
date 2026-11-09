#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Checks that apt refuses the .deb of berigna on a distribution below its minimum versions
# (ADR-0023; first case: Ubuntu 24.04 LTS, outside the supported family by decision of the
# owner): the user must get a clear message from apt, never a berigna that fails when it
# signs. Only simulates the installation (apt-get -s); runs as root in a container.
#
#   scripts/probar-rechazo.sh DIRECTORIO_CON_LOS_DEB [PAQUETE...]
#
# The packages are the dependencies apt must name as unmet (all of them, so that a change
# of the Depends that lets one through shows). Locally:
#   podman run --rm -v "$PWD:/src:ro" ubuntu:24.04 sh -c 'cd /src &&
#       scripts/probar-rechazo.sh build/paquetes python3-cryptography python3-pyscard python3-signxml'
set -eu
DEBS=$(realpath "${1:?uso: $0 DIRECTORIO_CON_LOS_DEB [PAQUETE...]}")
shift
. /etc/os-release
. "$(dirname "$0")/espejo-ubuntu.sh"
apt-get update -qq
SALIDA=$(mktemp)
# Every .deb of the folder, so that python3-pyhanko is never what is missing.
if LC_ALL=C apt-get install -s --no-install-recommends "$DEBS"/*.deb >"$SALIDA" 2>&1; then
  cat "$SALIDA"
  echo "apt instalaría berigna en $PRETTY_NAME: el Depends no lo rechaza" >&2
  exit 1
fi
cat "$SALIDA"
# Only the unmet dependencies of berigna itself: python3-pyhanko fails here too, and its
# lines must not stand in for a bound that berigna's Depends lost.
BERIGNA=$(awk '/^ berigna :/ { dentro = 1 } dentro && /^ [^ ]+ :/ && !/^ berigna :/ { dentro = 0 }
  dentro' "$SALIDA")
for paquete in "$@"; do
  printf '%s\n' "$BERIGNA" | grep -qF "Depends: $paquete " || {
    echo "apt rechaza berigna en $PRETTY_NAME, pero no por $paquete" >&2
    exit 1
  }
done
echo "apt rechaza berigna en $PRETTY_NAME: $*"
