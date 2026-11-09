#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Weekly watch of the published APT repository (DP-24, BRG-DSP-001 §4, BRG-MAN-001 §5): what a
# new user does, through the CDN, on a clean system. Fails, so that vigilancia.yml opens an
# issue, when
#   - the published key, or the one the package noggalito-archive-keyring installs, is not the
#     one of the documentation (packaging/noggalito-archive-keyring/huella), holds another key
#     too, or its primary key or signing subkey expires in less than DIAS_AVISO days (90 by
#     default: renewal is due three months before);
#   - apt refuses the repository (a bad or expired signature, a challenge of the CDN's bot
#     protection, the server down);
#   - berigna does not install from it, or its version is behind the latest release on GitHub.
# Runs as root in a container (it changes apt's sources and installs packages).
#
#   scripts/vigilar-repositorio.sh
set -eu
cd "$(dirname "$0")/.."
if [ ! -e /run/.containerenv ] && [ ! -e /.dockerenv ] && [ -z "${GITHUB_ACTIONS:-}" ]; then
  echo "solo dentro de un contenedor: cambia las fuentes de apt e instala paquetes" >&2
  exit 2
fi
URL=https://noggalito.com/apps/deb
HUELLA=$(cat packaging/noggalito-archive-keyring/huella)
DIAS_AVISO=${DIAS_AVISO:-90}
. /etc/os-release
echo "sistema: $PRETTY_NAME"
echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
. scripts/espejo-ubuntu.sh
rm -f /etc/dpkg/dpkg.cfg.d/excludes  # Ubuntu's minimised image: a real install keeps every file
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ca-certificates curl gnupg >/dev/null

# A keyring holds exactly the key of the documentation, and neither its primary key nor its
# newest signing subkey expires within DIAS_AVISO days (an expired primary invalidates every
# signature of its subkeys). An empty expiry field means the key never expires.
comprobar_clave() {
  datos=$(gpg --show-keys --with-colons "$1")
  [ "$(printf '%s\n' "$datos" | grep -c '^pub:')" -eq 1 ] ||
    { echo "$1 no tiene exactamente una clave" >&2; exit 1; }
  [ "$(printf '%s\n' "$datos" | awk -F: '/^pub:/ { p = 1; next } p && /^fpr:/ { print $10; exit }')" = "$HUELLA" ] ||
    { echo "la clave de $1 no tiene la huella $HUELLA" >&2; exit 1; }
  limite=$(( $(date +%s) + DIAS_AVISO * 86400 ))
  for tipo in pub sub; do
    # pub: the primary; sub: the signing subkeys still valid (not revoked, expired or disabled).
    vence=$(printf '%s\n' "$datos" | awk -F: -v t="$tipo" '$1 == t && (t == "pub" || ($12 ~ /s/ && $2 !~ /[rex]/)) { print ($7 == "" ? NUNCA : $7) }' NUNCA=99999999999 | sort -n | tail -1)
    [ -n "$vence" ] || { echo "$1 no tiene una subclave de firma vigente" >&2; exit 1; }
    if [ "$vence" -eq 99999999999 ]; then echo "$1: $tipo sin caducidad"; continue; fi
    echo "$1: $tipo vigente hasta $(date -u -d "@$vence" +%F)"
    [ "$vence" -gt "$limite" ] ||
      { echo "$1: $tipo caduca en menos de $DIAS_AVISO días: renovar (BRG-MAN-001 §10)" >&2; exit 1; }
  done
}

echo "== clave publicada"
LLAVERO=/usr/share/keyrings/noggalito-archive-keyring.asc
curl -fsSL -o "$LLAVERO" "$URL/noggalito-archive-keyring.asc"
comprobar_clave "$LLAVERO"

echo "== apt, como un usuario nuevo (README)"
curl -fsSL -o /etc/apt/sources.list.d/noggalito.sources "$URL/noggalito.sources"
apt-get update >/tmp/update.txt 2>&1 || true
cat /tmp/update.txt
# apt only warns about a repository it cannot use; here any warning about it is a failure.
# A failure of the distribution's own mirror is told apart: it is not the repository's fault.
if grep -E '^(E|W|Err):' /tmp/update.txt | grep -q 'noggalito'; then
  echo "apt no acepta el repositorio de noggalito" >&2; exit 1
fi
if grep -qE '^(E|Err):' /tmp/update.txt; then
  echo "falló el espejo de $NAME, no el repositorio de noggalito: repetir más tarde" >&2; exit 1
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
  berigna noggalito-archive-keyring </dev/null >/tmp/instalacion.txt 2>&1 ||
  { tail -20 /tmp/instalacion.txt; echo "berigna no se instala desde el repositorio" >&2; exit 1; }
INSTALADA=$(dpkg-query -W -f '${Version}' berigna)
echo "instalado: berigna $INSTALADA, noggalito-archive-keyring $(dpkg-query -W -f '${Version}' noggalito-archive-keyring)"
# What existing users' apt uses from now on: the key of the package, which replaced the one
# downloaded by hand.
echo "== clave del paquete noggalito-archive-keyring"
comprobar_clave "$LLAVERO"

echo "== versión publicada frente a GitHub"
# The token of the workflow, when there is one, avoids the limit of anonymous calls. python3
# is there: berigna depends on it.
ULTIMA=$(curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
  https://api.github.com/repos/noggalito/berigna/releases/latest |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"].removeprefix("v"))')
# v0.3.0 is 0.3.0 in Debian, v0.4.0-rc.1 is 0.4.0~rc.1. The repository may be ahead of GitHub's
# latest release (a release candidate), never behind.
ESPERADA=$(printf %s "$ULTIMA" | tr - '~')
dpkg --compare-versions "$INSTALADA" ge "$ESPERADA" ||
  { echo "el repositorio tiene berigna $INSTALADA; la última versión en GitHub es $ULTIMA: falta publicarla" >&2; exit 1; }
echo "repositorio publicado al día en $PRETTY_NAME: berigna $ULTIMA"
