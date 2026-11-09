#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Builds the APT repository of noggalito (DP-24, BRG-DSP-001 §3) in RAIZ, without state:
# the .deb given are copied into pool/ (next to the ones already there, which are never
# rewritten), and dists/ is regenerated from the whole pool/ with apt-ftparchive. Signing is
# a separate step (scripts/firmar-repositorio.sh): this script never touches a key.
#
#   scripts/armar-repositorio.sh RAIZ [PAQUETE.deb...]
#
# One suite, "stable", component "main", for the whole Debian family (ADR-0023); the
# packages are Architecture: all and appear in the indices of amd64 and arm64. Acquire-By-Hash:
# a client that updates while the repository is being published never mixes old and new
# indices behind the CDN cache.
set -eu
RAIZ=${1:?uso: $0 RAIZ [PAQUETE.deb...]}
shift
# The key that must sign this repository (Release: Signed-By); the CI uses a test key.
FINGERPRINT=${REPOSITORIO_HUELLA:-$(cat "$(dirname "$0")/../packaging/noggalito-archive-keyring/huella")}
mkdir -p "$RAIZ/pool/main"
RAIZ=$(realpath "$RAIZ")

for deb in "$@"; do
  nombre=$(dpkg-deb -f "$deb" Package)
  version=$(dpkg-deb -f "$deb" Version)
  arquitectura=$(dpkg-deb -f "$deb" Architecture)
  fuente=$(dpkg-deb -f "$deb" Source | cut -d' ' -f1)
  fuente=${fuente:-$nombre}
  case $fuente in lib?*) inicial=$(printf %s "$fuente" | cut -c1-4) ;; *) inicial=$(printf %s "$fuente" | cut -c1) ;; esac
  destino="$RAIZ/pool/main/$inicial/$fuente/${nombre}_${version#*:}_$arquitectura.deb"
  if [ -e "$destino" ]; then
    # A published version is immutable (the CDN keeps pool/ for a year): the same name
    # with other bytes is an error, never an overwrite.
    cmp -s "$deb" "$destino" || { echo "ya publicado con otro contenido: $destino" >&2; exit 1; }
  else
    mkdir -p "$(dirname "$destino")"
    cp "$deb" "$destino"
    chmod 0644 "$destino"
  fi
done

CONF=$(mktemp)
CACHE=$(mktemp -d)  # apt-ftparchive's database: thrown away, the repository keeps no state
trap 'rm -rf "$CONF" "$CACHE"' EXIT
cat >"$CONF" <<EOF
Dir { ArchiveDir "$RAIZ"; CacheDir "$CACHE"; };
Default { Packages::Compress ". xz"; Contents::Compress "xz"; };
TreeDefault {
  Directory "pool/\$(SECTION)";
  Packages "\$(DIST)/\$(SECTION)/binary-\$(ARCH)/Packages";
  Contents "\$(DIST)/\$(SECTION)/Contents-\$(ARCH)";
};
Tree "dists/stable" { Sections "main"; Architectures "amd64 arm64"; };
EOF

rm -rf "$RAIZ/dists"
mkdir -p "$RAIZ/dists/stable/main/binary-amd64" "$RAIZ/dists/stable/main/binary-arm64"
cd "$RAIZ"
apt-ftparchive -q -o APT::FTPArchive::DoByHash=true generate "$CONF"
# apt-ftparchive reports its errors but exits 0: the index must exist and list every .deb.
en_pool=$(find pool -name '*.deb' | wc -l)
for arch in amd64 arm64; do
  en_indice=$(grep -c '^Package:' "dists/stable/main/binary-$arch/Packages" || true)
  [ "$en_indice" -eq "$en_pool" ] || { echo "binary-$arch lista $en_indice de $en_pool .deb" >&2; exit 1; }
done
apt-ftparchive -q \
  -o APT::FTPArchive::DoByHash=true \
  -o APT::FTPArchive::Release::Origin=noggalito \
  -o APT::FTPArchive::Release::Label=noggalito \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
  -o APT::FTPArchive::Release::Components=main \
  -o APT::FTPArchive::Release::Acquire-By-Hash=yes \
  -o APT::FTPArchive::Release::Signed-By="$FINGERPRINT" \
  -o APT::FTPArchive::Release::Description="Paquetes de noggalito (https://noggalito.com/apps/)" \
  release dists/stable >dists/stable/Release.nuevo
mv dists/stable/Release.nuevo dists/stable/Release
find dists -type d -exec chmod 0755 {} + && find dists -type f -exec chmod 0644 {} +
echo "repositorio armado en $RAIZ (sin firmar):"
grep -c '^Package:' dists/stable/main/binary-amd64/Packages | sed 's/^/  paquetes: /'
