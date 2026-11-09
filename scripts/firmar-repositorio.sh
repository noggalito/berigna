#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Signs the Release of a repository built by scripts/armar-repositorio.sh (DP-24): InRelease
# (inline) and Release.gpg (detached), with the signing subkey of noggalito, which lives
# only in the owner's keyring (the primary key stays offline). gpg asks for the passphrase.
# Both signatures are then checked with sqv, the verifier of apt, against the keyring that
# the users install: a signature apt would refuse never leaves this machine.
#
#   scripts/firmar-repositorio.sh RAIZ
#
# For the CI's test repository: FIRMA_CLAVE (the fingerprint of the signing key) and
# FIRMA_LLAVERO (the public key to check against).
set -eu
RAIZ=${1:?uso: $0 RAIZ}
cd "$(dirname "$0")/.."
CLAVE=${FIRMA_CLAVE:-E21F94C58091EC144E40066E3F89E15C95A9B4F4}
LLAVERO=$(realpath "${FIRMA_LLAVERO:-packaging/noggalito-archive-keyring/keyrings/noggalito-archive-keyring.asc}")
cd "$RAIZ/dists/stable"
[ -f Release ] || { echo "no hay dists/stable/Release en $RAIZ" >&2; exit 1; }

rm -f InRelease Release.gpg
# "!": exactly this subkey, never another signing key of the same certificate.
gpg --local-user "$CLAVE!" --digest-algo SHA512 --clearsign --output InRelease Release
gpg --local-user "$CLAVE!" --digest-algo SHA512 --armor --detach-sign --output Release.gpg Release
chmod 0644 InRelease Release.gpg

TEMPORAL=$(mktemp -d)
FIRMADO="$TEMPORAL/Release"  # sqv never overwrites: a fresh name
trap 'rm -rf "$TEMPORAL"' EXIT
sqv --keyring "$LLAVERO" Release.gpg Release >/dev/null
sqv --keyring "$LLAVERO" --message --output "$FIRMADO" InRelease >/dev/null
# The signed text of InRelease is exactly Release (nothing added, nothing lost); a cleartext
# signature leaves out the line break before the signature (RFC 9580 §7.1).
{ cat "$FIRMADO"; echo; } | cmp -s - Release || { echo "InRelease no firma el mismo Release" >&2; exit 1; }
echo "firmado y comprobado con sqv: $(pwd)/InRelease y Release.gpg"
