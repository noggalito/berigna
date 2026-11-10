#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Publica una versión ya preparada, de principio a fin (BRG-DES-003): etiqueta, construye
# y comprueba (scripts/version.py etiquetar), sube la etiqueta, crea el release de GitHub y
# publica los .deb en el repositorio APT (scripts/publicar-repositorio.sh). Un solo comando
# en lugar de cuatro, con las comprobaciones al principio y mensajes claros.
#
#   SERVIDOR=alias-ssh scripts/publicar-version.sh 0.3.1
#
# Requisitos previos (falla al principio, con un mensaje, si falta alguno):
#   - la versión ya entró en main por PR (scripts/version.py preparar + fusión);
#   - main limpio e igual a origin/main;
#   - gh autenticado;
#   - SERVIDOR, el alias ssh del servidor del repositorio (BRG-DSP-001 §4; el alias está
#     en la documentación interna, no en el repositorio);
#   - piuparts pasado en la VM de Debian 13 con los tres paquetes (BRG-DSP-001 §8). En una
#     repetición, PIUPARTS_OK=1 salta la pregunta.
# gpg pide la frase de paso de la subclave de firma al firmar el repositorio. Los argumentos
# que siguen a la versión pasan a `version.py etiquetar` (por ejemplo, --constructor debuild).
set -eu
VERSION=${1:?uso: $0 VERSIÓN}
shift
DIRECTORIO="build/version/v$VERSION"

RAMA=$(git rev-parse --abbrev-ref HEAD)
[ "$RAMA" = main ] || { echo "estás en $RAMA; la versión se publica desde main (BRG-DES-003 §3)" >&2; exit 1; }
git diff --quiet || { echo "el árbol de trabajo no está limpio: confirma o guarda los cambios primero" >&2; exit 1; }
git fetch -q origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] ||
  { echo "main no está al día con origin/main: git pull --ff-only" >&2; exit 1; }

command -v gh >/dev/null || { echo "falta gh, el cliente de GitHub (https://cli.github.com/)" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh no está autenticado: gh auth login" >&2; exit 1; }

[ -n "${SERVIDOR:-}" ] || {
  echo "falta SERVIDOR, el alias ssh del servidor del repositorio (BRG-DSP-001 §4);" >&2
  echo "el alias está en la documentación interna. Por ejemplo:" >&2
  echo "  SERVIDOR=maracuya $0 $VERSION" >&2
  exit 1
}

if [ "${PIUPARTS_OK:-}" != "1" ]; then
  printf '¿piuparts ya pasó en la VM de Debian 13 con los tres paquetes (BRG-DSP-001 §8)? [s/N] '
  read -r RESPUESTA
  case "$RESPUESTA" in
    s|S|si|sí|Si|Sí) ;;
    *)
      echo "pásalo en la VM y repite (BRG-DES-003 §5), o PIUPARTS_OK=1 si esta ejecución ya es una repetición" >&2
      exit 1
      ;;
  esac
fi

scripts/version.py etiquetar "$VERSION" "$@"

git push origin "v$VERSION"

case "$VERSION" in
  *-*) PRERELEASE="--prerelease" ;;
  *) PRERELEASE="" ;;
esac
gh release create "v$VERSION" "$DIRECTORIO"/*.deb "$DIRECTORIO/SHA256SUMS" \
  --notes-file "$DIRECTORIO/notas.md" $PRERELEASE

scripts/publicar-repositorio.sh "$DIRECTORIO"

echo "versión $VERSION publicada: release de GitHub y repositorio APT de noggalito"
