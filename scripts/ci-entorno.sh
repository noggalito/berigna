#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# The CI environment, shared by the workflows verificar and vigilancia: Debian's packages
# (ADR-0013) and a virtual environment that sees them; only pyHanko (not in Debian, SPK-05)
# and the development tools come from PyPI. Runs as root inside a debian container.
#
#   scripts/ci-entorno.sh            pyHanko 0.25.1, the one berigna is packaged with
#   scripts/ci-entorno.sh reciente   the latest pyHanko with its own dependencies (R-DES-08)
set -eu
PYHANKO=${1:-fija}
# Retries: run 40812048365 failed because deb.debian.org timed out, not because of the code.
echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates git gettext poppler-utils fonts-dejavu-core libpcsclite1 pcscd libccid \
  xmlsec1 \
  python3 python3-venv python3-packaging \
  python3-cryptography python3-asn1crypto python3-lxml python3-pyscard \
  python3-pyhanko-certvalidator python3-signxml python3-requests python3-reportlab \
  python3-qrcode python3-tzlocal python3-click python3-yaml python3-pil \
  meson ninja-build blueprint-compiler desktop-file-utils libglib2.0-bin libglib2.0-dev-bin xvfb xauth \
  python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-poppler-0.18 adwaita-icon-theme

git config --global --add safe.directory "$PWD"
python3 -m venv --system-site-packages .venv
.venv/bin/pip install --no-cache-dir \
  'pytest==8.3.5' 'hypothesis==6.130.5' 'mypy==1.15.0' 'pytest-cov==5.0.0' 'ruff==0.17.3'
if [ "$PYHANKO" = reciente ]; then
  # with its dependencies: the latest pyHanko needs newer cryptography and certvalidator
  # than Debian 13 has (SPK-05); they go into the virtual environment, over Debian's
  .venv/bin/pip install --no-cache-dir --upgrade pyHanko
else
  .venv/bin/pip install --no-cache-dir --no-deps 'pyHanko==0.25.1'
fi
.venv/bin/pip install --no-cache-dir --no-deps -e .
.venv/bin/pip list --format=freeze | grep -i -e '^pyhanko' -e '^cryptography' || true
