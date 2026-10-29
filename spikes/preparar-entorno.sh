#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Prepara, sin instalar nada en el sistema, el entorno de los spikes en spikes/.entorno/:
#   - paquetes Python de Debian 13 extraídos (versiones exactas de la distribución),
#   - pyHanko 0.25.1 (ADR-0013) desde PyPI, sin dependencias,
#   - Apache Maven 3.9.9 (suma SHA-512 verificada) y las dependencias de DSS 6.2 del arnés.
# Uso: sh spikes/preparar-entorno.sh   y después:   . spikes/.entorno/activar
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
ENV="$DIR/.entorno"
mkdir -p "$ENV/debs" "$ENV/root" "$ENV/tools"

cd "$ENV/debs"
apt-get download python3-pyhanko-certvalidator python3-asn1crypto python3-signxml python3-tzlocal \
  python3-qrcode python3-yaml python3-click python3-uritools python3-defusedxml python3-oscrypto \
  python3-lxml python3-requests python3-pil python3-pkcs11 python3-pyscard
for f in *.deb; do dpkg-deb -x "$f" "$ENV/root"; done

SITE="$ENV/root/usr/lib/python3/dist-packages"
python3 -m pip download --no-deps --only-binary=:all: pyHanko==0.25.1 -d "$ENV/debs"
echo "045a0999c5e3b22caad86e4fa11ef488c3fd7f5b5886c045ca11ffa24254c33c  $ENV/debs/pyHanko-0.25.1-py3-none-any.whl" | sha256sum -c -
python3 -m zipfile -e "$ENV/debs/pyHanko-0.25.1-py3-none-any.whl" "$SITE"

cd "$ENV/tools"
V=3.9.9
curl -fsSLO "https://archive.apache.org/dist/maven/maven-3/$V/binaries/apache-maven-$V-bin.tar.gz"
curl -fsSLO "https://archive.apache.org/dist/maven/maven-3/$V/binaries/apache-maven-$V-bin.tar.gz.sha512"
echo "$(cut -d' ' -f1 apache-maven-$V-bin.tar.gz.sha512)  apache-maven-$V-bin.tar.gz" | sha512sum -c -
tar xzf "apache-maven-$V-bin.tar.gz"

cd "$DIR/spk03/dssval"
"$ENV/tools/apache-maven-$V/bin/mvn" -q -B dependency:copy-dependencies -DoutputDirectory=lib
mkdir -p classes && javac -d classes -cp 'lib/*' src/main/java/brg/Validate.java

cat > "$ENV/activar" <<EOF
export PYTHONPATH="$SITE:$DIR/spk03"
EOF
echo "Entorno listo. Actívalo con:  . $ENV/activar"
