#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Installs the built .deb files in a Debian-family system and runs the test suite against
# the installed package, not against src/ (line of the single .deb, BRG-VIS-002; first
# target: Ubuntu 26.04 LTS). One deliverable per format: the same .deb built on Debian 13
# must install and pass on every supported distribution of the family. Runs as root inside
# a container, and refuses to run anywhere else: it changes the configuration of apt and dpkg
# and replaces any installed berigna. Never runs the HIL tests (no card reader, no PIN).
#
#   scripts/probar-paquete-instalado.sh DIRECTORIO_CON_LOS_DEB
#
# Locally, with the three .deb of scripts/empaquetar-*.sh copied to build/paquetes/ (a copy
# of the tree, so that nothing the tests write lands in the working tree):
#   podman run --rm -v "$PWD:/src:ro" ubuntu:26.04 \
#       sh -c 'cp -r /src /tmp/b && cd /tmp/b && scripts/probar-paquete-instalado.sh build/paquetes'
set -eu
DEBS=${1:?uso: $0 DIRECTORIO_CON_LOS_DEB}
# Absolute: apt takes a local .deb only when its path has a slash at the start (or ./).
DEBS=$(realpath "$DEBS")
cd "$(dirname "$0")/.."

# Podman leaves /run/.containerenv, Docker /.dockerenv; GitHub Actions runs this in a
# container job.
if [ ! -e /run/.containerenv ] && [ ! -e /.dockerenv ] && [ -z "${GITHUB_ACTIONS:-}" ]; then
  echo "solo dentro de un contenedor: cambia apt y dpkg e instala berigna" >&2
  exit 2
fi

# One .deb of each package: several versions in the folder would leave apt to choose.
paquete() {
  nombre=$1
  set -- "$DEBS"/"$nombre"_*_all.deb
  [ $# -eq 1 ] && [ -e "$1" ] || { echo "hace falta exactamente un $nombre en $DEBS" >&2; exit 2; }
  echo "$1"
}
BERIGNA=$(paquete berigna)
NAUTILUS=$(paquete berigna-nautilus)
PYHANKO=$(paquete python3-pyhanko)

echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
# The container images of Ubuntu are minimised: dpkg drops /usr/share/locale, and with it the
# catalogues of berigna, which a real installation keeps. Without the rule they are installed.
rm -f /etc/dpkg/dpkg.cfg.d/excludes
. /etc/os-release
echo "sistema: $PRETTY_NAME"
apt-get update
# The packages under test, with their dependencies from this distribution; berigna-nautilus
# too (it pulls python3-nautilus), so that its postinst runs. Then the tools of the suite
# only: Xvfb, xmlsec1 (XAdES digests), pdftotext (PDF reports), GNU gettext and the ITS
# rules of appstream (the tests of the catalogues compile and extract po/ themselves); pytest
# and hypothesis from PyPI, at the versions of the Debian 13 CI (scripts/requisitos-pruebas.txt).
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  "$BERIGNA" "$NAUTILUS" "$PYHANKO"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates python3-venv xvfb xauth xmlsec1 poppler-utils gettext appstream adwaita-icon-theme
python3 -m venv --system-site-packages /tmp/venv-pruebas
/tmp/venv-pruebas/bin/pip install --no-cache-dir -r scripts/requisitos-pruebas.txt

python3 --version
dpkg-query -W -f '${Package} ${Version}\n' berigna python3-pyhanko python3-pyhanko-certvalidator \
  python3-cryptography python3-lxml python3-signxml python3-pyscard python3-gi libadwaita-1-0

# The installed package, never src/: pytest is told to look only in tests/ (the pythonpath
# of pyproject.toml also lists src), and the import is checked before anything runs.
/tmp/venv-pruebas/bin/python - <<'EOF'
import berigna, pyhanko
assert berigna.__file__.startswith("/usr/lib/python3/dist-packages/"), berigna.__file__
print("berigna desde", berigna.__file__, "· pyHanko", pyhanko.__version__)
EOF

# What the installed launcher sets (bin/berigna.in), and the installed schema; the Nautilus
# extension is imported from where berigna-nautilus puts it.
export BERIGNA_RESOURCES=/usr/share/berigna/berigna.gresource
export BERIGNA_LOCALEDIR=/usr/share/locale
export GSETTINGS_SCHEMA_DIR=/usr/share/glib-2.0/schemas
export PYTHONPATH=/usr/share/nautilus-python/extensions
export BERIGNA_TEST_DISPLAY=1
# Every module of the package imported with the warnings of berigna turned into errors: a
# library of this distribution that deprecates something berigna calls shows here, before
# it breaks (the warnings of the libraries themselves, such as signxml's, are theirs).
xvfb-run -a /tmp/venv-pruebas/bin/python - <<'EOF'
import importlib, pkgutil, warnings
warnings.filterwarnings("error", module=r"berigna(_nautilus)?(\.|$)")
import berigna
modules = pkgutil.walk_packages(berigna.__path__, "berigna.")
names = [m.name for m in modules if m.name != "berigna.__main__"]  # it starts berigna
for name in ["berigna_nautilus", *names]:
    importlib.import_module(name)
print(len(names) + 1, "módulos importados sin avisos de berigna")
EOF

# Left out: the SBOM test describes the CI environment of scripts/ci-entorno.sh (pyHanko
# from PyPI), not an installed system; the scripts are development tools, not the package.
xvfb-run -a -s "-screen 0 1280x1024x24" \
  /tmp/venv-pruebas/bin/python -m pytest -o pythonpath=tests -p no:cacheprovider -q \
  --deselect tests/unit/test_scripts.py::test_the_sbom_lists_what_berigna_needs_at_run_time
