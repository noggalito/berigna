# Entorno de desarrollo y convenciones

| Campo | Valor |
|---|---|
| Documento | BRG-DES-001 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Estructura prevista del repositorio

```
berigna/
├── meson.build
├── pyproject.toml                # herramientas: ruff, mypy, pytest
├── LICENSE                       # GPL-3.0
├── README.md
├── SECURITY.md
├── CHANGELOG.md
├── src/berigna/
│   ├── __init__.py
│   ├── main.py                   # Adw.Application
│   ├── core/
│   │   ├── token/                # backends: dnie_v2 (APDU) y pkcs11
│   │   ├── formats/{pades,cades,xades}/
│   │   ├── trust/
│   │   ├── net/
│   │   ├── appearance/
│   │   ├── signing.py
│   │   ├── validation.py
│   │   ├── batch.py
│   │   ├── report/
│   │   ├── history.py
│   │   └── config.py
│   └── ui/
│       ├── window.py
│       ├── views/
│       ├── dialogs/
│       └── blueprints/*.blp
├── nautilus/berigna_nautilus.py
├── data/
│   ├── pe.berigna.Berigna.desktop.in
│   ├── pe.berigna.Berigna.metainfo.xml.in
│   ├── pe.berigna.Berigna.gschema.xml
│   ├── icons/
│   └── trust/                    # certificados IOFE + manifest.json
├── po/
│   ├── LINGUAS                   # es_PE
│   ├── POTFILES.in
│   └── es_PE.po                  # traducción completa (el texto fuente es en_US)
├── help/
│   ├── C/                        # manual de usuario, fuente en_US (Mallard)
│   └── es_PE/es_PE.po            # traducción del manual (itstool)
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── interop/
│   ├── fuzz/
│   ├── pki/                      # generador de la PKI de pruebas
│   └── fixtures/
├── debian/
└── docs/                         # esta documentación
```

## 2. Dependencias del entorno de desarrollo (Debian 13)

Lista preliminar; SPK-05 la confirma:

```bash
sudo apt install \
  python3 python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 \
  gir1.2-poppler-0.18 blueprint-compiler meson ninja-build gettext itstool \
  locales \
  desktop-file-utils appstream \
  pcscd libccid pcsc-tools opensc softhsm2 \
  python3-cryptography python3-asn1crypto python3-lxml python3-pil \
  python3-pyscard python3-pkcs11 python3-pyhanko-certvalidator python3-signxml \
  python3-requests python3-babel python3-reportlab python3-qrcode python3-tzlocal \
  python3-click python3-yaml python3-defusedxml python3-barcode python3-fonttools \
  python3-pytest python3-hypothesis \
  python-nautilus \
  devscripts debhelper dh-python lintian piuparts
```

La única dependencia que no está en Debian 13 es pyHanko (SPK-05). En desarrollo se instala `pyHanko==0.25.1` sin dependencias (`pip install --no-deps`) en un *virtualenv* con `--system-site-packages`, para usar exactamente las versiones de Debian. En producción se usa el `.deb` del proyecto (ADR-0013).

### 2.1 Entorno de desarrollo sin privilegios

Si no se pueden instalar paquetes del sistema, se usa un entorno virtual que reutiliza los de Debian (`cryptography`, etc.):

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/pip install 'pytest==8.3.5' 'hypothesis==6.130.5' 'mypy==1.15.0' 'pytest-cov==5.0.0' ruff
.venv/bin/pip install --no-deps -e .   # berigna en modo editable (scripts HIL incluidos)
```

pyscard no tiene un *wheel* para Python 3.13 en PyPI y compilarlo requiere `libpcsclite-dev` y `swig`. Se usa `python3-pyscard` de Debian (`sudo apt install python3-pyscard`), que el entorno virtual ve gracias a `--system-site-packages`.

Comprobaciones antes de cada commit:

```bash
.venv/bin/ruff format --check src tests && .venv/bin/ruff check src tests
.venv/bin/mypy
.venv/bin/pytest --cov=berigna
```

El script `scripts/verificar.sh` ejecuta exactamente esas comprobaciones (nunca las pruebas HIL). Se puede instalar como *hook* de `pre-push` con `ln -s ../../scripts/verificar.sh .git/hooks/pre-push`.

## 3. Estilo de código

| Aspecto | Norma |
|---|---|
| Formato y *lint* | `ruff format` y `ruff check` (incluidas las reglas de seguridad `S`) |
| Tipos | `mypy --strict` en `berigna.core`; en `ui`, modo normal |
| Nombres | Código e identificadores en inglés |
| Cadenas de la interfaz | Texto fuente en inglés (en_US) dentro de `_()`, con comentarios para traductores (`# Translators:`) cuando el contexto no sea obvio. Toda cadena nueva debe llegar con su traducción a `po/es_PE.po` en el mismo PR (ADR-0011). Nada de concatenar frases: se usan marcadores con nombre (`_("Signed by {name}").format(name=…)`) y `ngettext` para los plurales |
| Configuración regional en desarrollo | Generar `es_PE.UTF-8` y `en_US.UTF-8` con `sudo dpkg-reconfigure locales` para poder probar ambos idiomas |
| Comentarios y *docstrings* | En inglés. La documentación de producto, en español |
| Cabeceras | `# SPDX-License-Identifier: GPL-3.0-or-later` y `# SPDX-FileCopyrightText: <año> {{TITULAR}}` |
| Errores | Jerarquía `BerignaError` con un código (`ERR-xxx`) vinculado al catálogo de mensajes de UX |
| Registros | El módulo `logging`, con un filtro que elimina los tipos sensibles (`Pin`, `bytes` del documento) |

## 4. Flujo de trabajo con git

- Rama principal `main`, siempre publicable. Ramas `feat/…`, `fix/…`, `docs/…`.
- Commits según Conventional Commits, con DCO (`Signed-off-by`).
- Toda integración en `main` pasa por una revisión y por la CI en verde.
- Los cambios que afectan a `core/token`, `core/formats`, `core/trust` o a la seguridad requieren una revisión adicional y una entrada en el registro de cambios de seguridad.

## 5. Integración continua

Pasos mínimos del *pipeline*:
1. `ruff` (incluidas las reglas `S` de flake8-bandit, que sustituyen a ejecutar bandit por separado) y `mypy --strict`.
2. Pruebas unitarias y de integración con SoftHSM. La cobertura mínima es del 80 % (`fail_under` en `pyproject.toml`); las rutas críticas de firma, validación y *token* deben quedar cubiertas por completo (RNF-MAN-02).
3. Validación de la matriz de formatos con DSS 6.2: JAR oficiales de Maven Central y un arnés Java mínimo, sin Docker ni imágenes de terceros (SPK-03 §2). Se exige TOTAL_PASSED y PASSED en cada sello.
4. *Fuzzing* corto (5 min por objetivo) en cada PR; largo cada noche.
5. Compilación del `.deb`, `lintian` y `piuparts`.
6. `pip-audit` y verificación de licencias.
7. Comprobaciones de internacionalización PR-I18N-01, 02, 04, 06 y 07 (07-calidad §8).

## 6. Versionado y publicación

- SemVer para la aplicación (`MAYOR.MENOR.PARCHE`).
- Las etiquetas git van firmadas (`git tag -s vX.Y.Z`).
- Cada publicación incluye el registro de cambios, el *hash* SHA-256 del `.deb`, las evidencias de las pruebas (07-calidad §9) y una nota que indica si la versión está acreditada.
- La versión acreditada se mantiene en una rama `release/X.Y` y solo recibe correcciones de seguridad evaluadas según el procedimiento de INDECOPI (SPK-04, pregunta 7).
