#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Weekly watch of the published APT repository (DP-24, BRG-DSP-001 §4, BRG-MAN-001 §5): what a
# new user does, through the CDN, on a clean system. Fails, so that vigilancia.yml opens an
# issue, when
#   - the published key is not the one of the documentation, or its signing subkey expires in
#     less than DIAS_AVISO days (90 by default: renewal is due three months before);
#   - apt refuses the repository (a bad or expired signature, a challenge of the CDN's bot
#     protection, the server down);
#   - berigna does not install from it, or its version is not the latest release on GitHub.
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
HUELLA=A99859F6A32D8D5DEE5D3609CEA6BD335F594929
DIAS_AVISO=${DIAS_AVISO:-90}
. /etc/os-release
echo "sistema: $PRETTY_NAME"
echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
. scripts/espejo-ubuntu.sh
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  ca-certificates curl gnupg >/dev/null

echo "== clave publicada"
LLAVERO=/usr/share/keyrings/noggalito-archive-keyring.asc
curl -fsSL -o "$LLAVERO" "$URL/noggalito-archive-keyring.asc"
CLAVE=$(gpg --show-keys --with-colons "$LLAVERO")
printf '%s\n' "$CLAVE" | grep -q "^fpr:::::::::$HUELLA:\$" ||
  { echo "la clave publicada no tiene la huella $HUELLA" >&2; exit 1; }
# The signing subkey (capability s) still valid for DIAS_AVISO days; field 7 is its expiry.
LIMITE=$(( $(date +%s) + DIAS_AVISO * 86400 ))
VENCE=$(printf '%s\n' "$CLAVE" | awk -F: '$1 == "sub" && $12 ~ /s/ && $2 !~ /[rex]/ { print $7 }' | sort -n | tail -1)
[ -n "$VENCE" ] || { echo "la clave publicada no tiene una subclave de firma vigente" >&2; exit 1; }
echo "subclave de firma vigente hasta $(date -u -d "@$VENCE" +%F)"
[ "$VENCE" -gt "$LIMITE" ] ||
  { echo "la subclave de firma caduca en menos de $DIAS_AVISO días: renovar (BRG-MAN-001 §10)" >&2; exit 1; }

echo "== apt, como un usuario nuevo (README)"
curl -fsSL -o /etc/apt/sources.list.d/noggalito.sources "$URL/noggalito.sources"
apt-get update >/tmp/update.txt 2>&1 || true
cat /tmp/update.txt
# apt only warns about a repository it cannot use; here any warning about it is a failure.
if grep -E '^(E|W|Err):' /tmp/update.txt | grep -q 'noggalito'; then
  echo "apt no acepta el repositorio de noggalito" >&2; exit 1
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
  berigna noggalito-archive-keyring </dev/null >/tmp/instalacion.txt 2>&1 ||
  { tail -20 /tmp/instalacion.txt; echo "berigna no se instala desde el repositorio" >&2; exit 1; }
INSTALADA=$(dpkg-query -W -f '${Version}' berigna)
echo "instalado: berigna $INSTALADA, noggalito-archive-keyring $(dpkg-query -W -f '${Version}' noggalito-archive-keyring)"

echo "== versión publicada frente a GitHub"
# The token of the workflow, when there is one, avoids the limit of anonymous calls.
ULTIMA=$(curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
  https://api.github.com/repos/noggalito/berigna/releases/latest |
  sed -n 's/^ *"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p')
[ -n "$ULTIMA" ] || { echo "no se pudo leer la última versión de GitHub" >&2; exit 1; }
# 0.3.0-1 is the Debian form of v0.3.0; 0.4.0~rc.1-1 that of v0.4.0-rc.1.
[ "${INSTALADA%-*}" = "$(printf %s "$ULTIMA" | tr - '~')" ] ||
  { echo "el repositorio tiene berigna ${INSTALADA%-*}; la última versión en GitHub es $ULTIMA: falta publicarla" >&2; exit 1; }
echo "repositorio publicado al día en $PRETTY_NAME: berigna $ULTIMA"
