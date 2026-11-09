#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Publishes .deb files in the APT repository of noggalito, https://noggalito.com/apps/deb/
# (DP-24, BRG-DSP-001 §3). Runs on the owner's workstation, the only place with the signing
# subkey: the CI never gets a credential of the server.
#
#   SERVIDOR=alias-ssh scripts/publicar-repositorio.sh DIRECTORIO_CON_LOS_DEB
#
# The folder needs its SHA256SUMS (the one of a GitHub release, or of scripts/compilar-paquetes.sh):
# every .deb is checked against it first. Then:
#   1. pool/ is brought from the server (the published packages, never changed);
#   2. the repository is rebuilt from pool/ plus the new .deb (scripts/armar-repositorio.sh);
#   3. it is signed and checked with sqv (scripts/firmar-repositorio.sh; gpg asks for the
#      passphrase);
#   4. it is uploaded in the order that never shows an index pointing to a missing file:
#      pool/, then the indices and their by-hash copies, the signed Release files last.
#
# SERVIDOR is the ssh alias of the server (its name and address are kept in the internal
# documentation, not here); DESTINO defaults to /srv/paquetes/deb. SOLO_ARMAR=1 stops before
# the upload, to look at build/repositorio first.
set -eu
DEBS=$(realpath "${1:?uso: $0 DIRECTORIO_CON_LOS_DEB}")
cd "$(dirname "$0")/.."
SERVIDOR=${SERVIDOR:?falta SERVIDOR, el alias ssh del servidor del repositorio}
DESTINO=${DESTINO:-/srv/paquetes/deb}
RAIZ=build/repositorio
LLAVERO=packaging/noggalito-archive-keyring/keyrings/noggalito-archive-keyring.asc

[ -f "$DEBS/SHA256SUMS" ] || { echo "falta $DEBS/SHA256SUMS" >&2; exit 1; }
(cd "$DEBS" && sha256sum --check --strict SHA256SUMS)
set -- "$DEBS"/*.deb
[ -e "$1" ] || { echo "no hay .deb en $DEBS" >&2; exit 1; }
for deb in "$@"; do
  grep -q " \(\./\)\{0,1\}$(basename "$deb")\$" "$DEBS/SHA256SUMS" ||
    { echo "$(basename "$deb") no está en SHA256SUMS" >&2; exit 1; }
done

rm -rf "$RAIZ"
mkdir -p "$RAIZ/pool"
# The first publication finds no pool/ on the server yet.
if ssh "$SERVIDOR" test -d "$DESTINO/pool"; then
  rsync -a "$SERVIDOR:$DESTINO/pool/" "$RAIZ/pool/"
fi
scripts/armar-repositorio.sh "$RAIZ" "$@"
scripts/firmar-repositorio.sh "$RAIZ"
# What a new user downloads first (BRG-DSP-001 §3): the key and the deb822 source.
cp "$LLAVERO" packaging/noggalito-archive-keyring/noggalito.sources "$RAIZ/"
chmod 0644 "$RAIZ/noggalito-archive-keyring.asc" "$RAIZ/noggalito.sources"

if [ -n "${SOLO_ARMAR:-}" ]; then
  echo "armado y firmado en $RAIZ; sin subir (SOLO_ARMAR)"
  exit 0
fi
# --ignore-existing in pool/: a published .deb is never replaced (the CDN keeps it a year).
rsync -a --ignore-existing "$RAIZ/pool/" "$SERVIDOR:$DESTINO/pool/"
# Without --delete: the by-hash copies of earlier indices stay for the clients in the middle
# of an update.
rsync -a --exclude InRelease --exclude Release --exclude Release.gpg \
  "$RAIZ/dists/" "$SERVIDOR:$DESTINO/dists/"
rsync -a "$RAIZ/dists/stable/Release" "$RAIZ/dists/stable/Release.gpg" \
  "$RAIZ/dists/stable/InRelease" "$SERVIDOR:$DESTINO/dists/stable/"
rsync -a "$RAIZ/noggalito-archive-keyring.asc" "$RAIZ/noggalito.sources" "$SERVIDOR:$DESTINO/"
# The by-hash copies of indices replaced more than two weeks ago: no client still needs them.
ssh "$SERVIDOR" find "$DESTINO/dists" -path "'*/by-hash/*'" -type f -mtime +14 -delete

# What the users get, through the CDN: the signature apt checks, with the published key.
COMPROBACION=$(mktemp -d)
trap 'rm -rf "$COMPROBACION"' EXIT
# A few tries: an edge of the CDN may take a moment to see the new file (dists/ is not cached,
# but a failure here never means the upload went wrong: run only this check again).
for intento in 1 2 3 4 5 6; do
  curl -fsS -H 'Cache-Control: no-cache' -o "$COMPROBACION/InRelease" \
    "https://noggalito.com/apps/deb/dists/stable/InRelease?comprobacion=$(date +%s)"
  cmp -s "$COMPROBACION/InRelease" "$RAIZ/dists/stable/InRelease" && break
  [ "$intento" -lt 6 ] || { echo "subido, pero la CDN todavía sirve otro InRelease" >&2; exit 1; }
  sleep 10
done
sqv --keyring "$LLAVERO" --message --output "$COMPROBACION/Release" "$COMPROBACION/InRelease" >/dev/null
echo "publicado: https://noggalito.com/apps/deb/ ($(grep -c '^Package:' "$RAIZ/dists/stable/main/binary-amd64/Packages") paquetes)"
