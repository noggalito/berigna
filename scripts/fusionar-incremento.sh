#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Fusiona el incremento revisado: verificar.sh → rama → commit firmado con el DCO → push →
# PR → CI → fusión.
#
# Pensado para revisar el incremento ANTES: el cambio vive sin commitear en el árbol de
# trabajo (o ya commiteado en cualquier rama); el script lo sube a una rama nueva, abre el
# PR contra main, espera a que la CI quede en verde y lo fusiona con un commit de fusión,
# como los PR anteriores. Ejecuta scripts/verificar.sh antes de tocar nada (revisión del
# 2026-11-01): la CI también lo ejecuta (gh pr checks), pero así no se sube nada que la
# puerta local ya rechaza.
#
#   scripts/fusionar-incremento.sh RAMA "asunto del commit (Conventional Commits)" ["cuerpo"]
#
# Ejemplo (Fase 4, incremento 4):
#   scripts/fusionar-incremento.sh feat/xades \
#     "feat(xades): firma XAdES envuelta, envolvente y separada de B-B a B-LTA (RF-030 a RF-033)" \
#     "Fase 4, incremento 4. Matriz externa en BRG-CAL-006 §3.3."
set -eu
cd "$(git rev-parse --show-toplevel)"

[ $# -ge 2 ] || { sed -n '4,18p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
BRANCH=$1
SUBJECT=$2
BODY=${3:-}

command -v gh >/dev/null || { echo "hace falta gh (GitHub CLI)"; exit 1; }
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
    echo "la rama $BRANCH ya existe"; exit 1
fi
if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    echo "el árbol de trabajo está limpio: no hay nada que fusionar"; exit 1
fi
# Los archivos nuevos no se añaden solos: git add -A se llevaba cualquier archivo suelto
# (revisión del 2026-11-01). Lo commiteado ya (en --cached) sí viaja con el incremento.
if [ -n "$(git ls-files --others --exclude-standard)" ]; then
    echo "hay archivos sin rastrear; añádelos con git add o quítalos:" >&2
    git ls-files --others --exclude-standard >&2
    exit 1
fi

echo "== Incremento a fusionar (aún sin commitear) =="
git status --short
git diff --stat
git diff --cached --stat
echo "rama: $BRANCH"
echo "commit: $SUBJECT"
[ -n "$BODY" ] && echo "cuerpo: $BODY"
printf '¿Fusionarlo (verificar.sh → rama → commit con DCO → push → PR → CI → merge)? [s/N] '
read -r ANSWER
case "$ANSWER" in s|S|si|sí|SI|SÍ) ;; *) echo "nada hecho"; exit 1 ;; esac

scripts/verificar.sh
git switch -c "$BRANCH"
git add -u
# -s añade el Signed-off-by del DCO (CONTRIBUTING); la firma del commit, la de la config.
if [ -n "$BODY" ]; then
    git commit -s -m "$SUBJECT" -m "$BODY"
else
    git commit -s -m "$SUBJECT"
fi
git push -u origin "$BRANCH"

if [ -n "$BODY" ]; then
    gh pr create --base main --title "$SUBJECT" --body "$BODY"
else
    gh pr create --base main --title "$SUBJECT"
fi

echo "== Esperando a la CI =="
gh pr checks "$BRANCH" --watch --fail-fast
gh pr merge "$BRANCH" --merge --delete-branch
git switch main
git pull --ff-only
echo "fusionado: $SUBJECT"
