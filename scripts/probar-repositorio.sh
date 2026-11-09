#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Tests the APT repository as apt sees it (DP-24, BRG-DSP-001 §3), with a throwaway key: the
# repository built by scripts/armar-repositorio.sh and signed by scripts/firmar-repositorio.sh,
# served from file://. Checks that apt
#   1. accepts the signature and installs berigna from it, with its dependencies from the
#      distribution;
#   2. upgrades to a newer version published later;
#   3. refuses a Release altered after signing, and one signed with another key;
# that armar-repositorio.sh refuses to overwrite a published .deb; and that the package
# noggalito-archive-keyring installs without a question over the key and source that the
# install instructions place by hand. Runs as root in a
# container (it changes apt's sources and installs packages).
#
#   scripts/probar-repositorio.sh DIRECTORIO_CON_LOS_DEB
set -eu
DEBS=$(realpath "${1:?uso: $0 DIRECTORIO_CON_LOS_DEB}")
cd "$(dirname "$0")/.."
if [ ! -e /run/.containerenv ] && [ ! -e /.dockerenv ] && [ -z "${GITHUB_ACTIONS:-}" ]; then
  echo "solo dentro de un contenedor: cambia las fuentes de apt e instala paquetes" >&2
  exit 2
fi
. /etc/os-release
echo "sistema: $PRETTY_NAME"
echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
rm -f /etc/dpkg/dpkg.cfg.d/excludes
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  apt-utils gnupg sqv xz-utils >/dev/null

TRABAJO=$(mktemp -d)
chmod 0755 "$TRABAJO"  # apt's file method reads it as _apt
export GNUPGHOME="$TRABAJO/gnupg"
mkdir -m 0700 "$GNUPGHOME"
nueva_clave() {
  gpg -q --batch --passphrase '' --quick-generate-key "$1 <prueba@example.invalid>" ed25519 sign 1d
  gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/{print $10; exit}'
}
CLAVE=$(nueva_clave prueba)
OTRA=$(nueva_clave otra)
gpg --armor --export "$CLAVE" > "$TRABAJO/prueba.asc"
chmod 0644 "$TRABAJO/prueba.asc"
export REPOSITORIO_HUELLA="$CLAVE" FIRMA_CLAVE="$CLAVE" FIRMA_LLAVERO="$TRABAJO/prueba.asc"

REPO="$TRABAJO/repo"
set -- "$DEBS"/berigna_*_all.deb "$DEBS"/berigna-nautilus_*_all.deb "$DEBS"/python3-pyhanko_*_all.deb
scripts/armar-repositorio.sh "$REPO" "$@"
scripts/firmar-repositorio.sh "$REPO"
chmod -R a+rX "$REPO"
cat > /etc/apt/sources.list.d/prueba.sources <<EOF
Types: deb
URIs: file://$REPO/
Suites: stable
Components: main
Signed-By: $TRABAJO/prueba.asc
EOF

echo "== 1. firma aceptada e instalación"
apt-get update -q
apt-cache policy berigna | sed -n 1,6p
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends berigna >/dev/null
ANTES=$(dpkg-query -W -f '${Version}' berigna)
echo "instalado: berigna $ANTES"

echo "== 2. actualización a una versión publicada después"
NUEVA="$ANTES+prueba1"
rm -rf "$TRABAJO/deb" && dpkg-deb -R "$DEBS/$(basename "$1")" "$TRABAJO/deb"
sed -i "s/^Version: .*/Version: $NUEVA/" "$TRABAJO/deb/DEBIAN/control"
dpkg-deb -b -Zxz "$TRABAJO/deb" "$TRABAJO/berigna_${NUEVA}_all.deb" >/dev/null
# berigna-nautilus depends on berigna (= its version): only berigna moves here.
scripts/armar-repositorio.sh "$REPO" "$TRABAJO/berigna_${NUEVA}_all.deb"
scripts/firmar-repositorio.sh "$REPO"
chmod -R a+rX "$REPO"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --only-upgrade berigna >/dev/null
DESPUES=$(dpkg-query -W -f '${Version}' berigna)
[ "$DESPUES" = "$NUEVA" ] || { echo "no se actualizó: $DESPUES" >&2; exit 1; }
echo "actualizado: berigna $DESPUES"

echo "== 3. un .deb publicado no se reemplaza"
cp "$TRABAJO/berigna_${NUEVA}_all.deb" "$TRABAJO/otro.deb" && printf x >> "$TRABAJO/otro.deb"
mkdir "$TRABAJO/otro" && mv "$TRABAJO/otro.deb" "$TRABAJO/otro/berigna_${NUEVA}_all.deb"
if scripts/armar-repositorio.sh "$REPO" "$TRABAJO/otro/berigna_${NUEVA}_all.deb" 2>/dev/null; then
  echo "armar-repositorio.sh reemplazó un .deb publicado" >&2; exit 1
fi
echo "rechazado: mismo nombre con otro contenido"

rechaza() {
  rm -rf /var/lib/apt/lists/*"$(echo "$REPO" | tr / _)"*
  if apt-get update -q >"$TRABAJO/update.txt" 2>&1 && ! grep -q '^[EW]: .*\(firma\|signature\|NO_PUBKEY\|not signed\|sin firmar\|InRelease\)' "$TRABAJO/update.txt"; then
    cat "$TRABAJO/update.txt"; echo "apt aceptó $1" >&2; exit 1
  fi
  grep -i 'firma\|signature\|NO_PUBKEY\|not signed\|sin firmar\|InRelease' "$TRABAJO/update.txt" | head -2
  echo "rechazado: $1"
}
echo "== 4. Release alterado después de firmar"
cp "$REPO/dists/stable/InRelease" "$TRABAJO/InRelease.bueno"
sed -i 's/^Label: noggalito/Label: alterado/' "$REPO/dists/stable/InRelease"
rm -f "$REPO/dists/stable/Release.gpg"
rechaza "un InRelease alterado"
cp "$TRABAJO/InRelease.bueno" "$REPO/dists/stable/InRelease"

echo "== 5. Release firmado con otra clave"
gpg --local-user "$OTRA!" --clearsign --output "$REPO/dists/stable/InRelease.otra" "$REPO/dists/stable/Release"
mv "$REPO/dists/stable/InRelease.otra" "$REPO/dists/stable/InRelease"
rechaza "un InRelease firmado con otra clave"

echo "== 6. noggalito-archive-keyring sobre la instalación a mano"
KEYRING=$(ls "$DEBS"/noggalito-archive-keyring_*_all.deb)
dpkg-deb -x "$KEYRING" "$TRABAJO/keyring"
cp "$TRABAJO/keyring/usr/share/keyrings/noggalito-archive-keyring.asc" /usr/share/keyrings/
cp "$TRABAJO/keyring/etc/apt/sources.list.d/noggalito.sources" /etc/apt/sources.list.d/
# No terminal: a conffile question would make dpkg fail here.
dpkg -i "$KEYRING" </dev/null >/dev/null
dpkg-query -W -f '${Package} ${Version} ${db:Status-Status}\n' noggalito-archive-keyring
grep -q '^Signed-By: /usr/share/keyrings/noggalito-archive-keyring.asc$' /etc/apt/sources.list.d/noggalito.sources
# The key shipped is the one of the repository, whose fingerprint the documentation publishes.
gpg --show-keys --with-colons /usr/share/keyrings/noggalito-archive-keyring.asc |
  grep -q '^fpr:::::::::A99859F6A32D8D5DEE5D3609CEA6BD335F594929:$'
rm /etc/apt/sources.list.d/noggalito.sources  # it points to the real repository

echo "repositorio comprobado en $PRETTY_NAME"
