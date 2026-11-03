# Entorno de desarrollo y convenciones

| Campo | Valor |
|---|---|
| Documento | BRG-DES-001 |
| Versión | 0.6.1 |
| Estado | Borrador |
| Fecha | 2026-11-03 |
| Responsable | noggalito |

## 1. Estructura del repositorio

Estado al 2026-10-28. Lo marcado con *(previsto)* todavía no existe.

```
berigna/
├── pyproject.toml                # metadatos del núcleo; ruff, mypy, pytest, coverage
├── meson.build                   # aplicación GTK (ADR-0010): vistas, esquema, catálogos, lanzador
├── bin/berigna.in                # lanzador instalado
├── LICENSE, README.md, SECURITY.md, CHANGELOG.md
├── .github/workflows/verificar.yml  # CI: scripts/verificar.sh en Debian 13, SBOM y rendimiento
├── .github/workflows/vigilancia.yml # semanal: Debian stable y testing, servicios, última pyHanko
├── .github/dependabot.yml        # solo las actions de GitHub, cada mes (BRG-MAN-001 §5)
├── scripts/verificar.sh          # verificación local, incluida la documentación (R-DES-05)
├── scripts/verificar-documentacion.py  # cabeceras, fechas e identificadores de docs/
├── scripts/hooks/pre-push        # gancho de pre-push con verificar.sh (R-DES-06)
├── scripts/traducciones.sh       # plantilla, catálogos y compilación a build/locale (gettext)
├── scripts/fusionar-incremento.sh  # rama → commit con DCO → push → PR → CI → fusión
├── scripts/ejecutar.sh           # lanza la interfaz desde el árbol de trabajo
├── scripts/ci-entorno.sh         # entorno de la CI: paquetes de Debian y .venv (las dos CI)
├── scripts/sbom.py               # lista de componentes CycloneDX 1.6 (R-DES-03)
├── scripts/rendimiento.py        # medidas con la tarjeta simulada y comparación (R-DES-10)
├── scripts/vigilar-servicios.py  # TSL de INDECOPI, CRL y OCSP de RENIEC, OSV de pyHanko
├── scripts/vulnerabilidades-debian.py  # debsecan sobre los paquetes de Debian del SBOM (R-DES-02)
├── src/berigna/
│   ├── core/
│   │   ├── errors.py             # jerarquía de errores ERR-xxx
│   │   ├── token/                # base (TokenSigner), pin, transport (PC/SC), dnie_v2 (APDU), monitor
│   │   ├── trust/                # store + anchors/ (IOFE, manifest.json); tsl + tsl/ (raíz de INDECOPI)
│   │   ├── validation/           # preflight (RF-006), pdf (verificación de firmas, RF-050), cades (RF-051) y spec (procesos ETSI compartidos)
│   │   ├── formats/              # pades (B-B a B-LTA); cades y xades (previstos, Fase 4)
│   │   ├── net/                  # fetchers (OCSP, CRL) y tsa (RFC 3161)
│   │   ├── report/               # messages, explanations (RF-053), json_report y pdf_report (RF-054)
│   │   ├── i18n.py               # idiomas es_PE y quechua, catálogos gettext (ADR-0015)
│   │   ├── signing.py            # orquestación de la firma de PDF
│   │   ├── documents.py          # tipo de documento abierto, páginas, firmas y SHA-256
│   │   └── appearance/, history.py, config.py, batch.py   # (previstos)
│   ├── main.py, __main__.py      # punto de entrada de la interfaz
│   ├── ui/                       # GTK 4 + libadwaita: application, window, presentation, i18n
├── data/
│   ├── brand/                    # logotipos SVG (GPL-3.0-or-later)
│   ├── ui/*.blp, berigna.gresource.xml   # vistas en Blueprint y recursos
│   ├── com.noggalito.Berigna.gschema.xml    # preferencias (GSettings)
│   └── *.desktop.in, *.metainfo.xml.in, icons/   # (previstos, Fases 3 y 5)
├── po/                           # LINGUAS, POTFILES, berigna.pot, es_PE.po, quz.po
├── help/                         # (previsto: manual Mallard)
├── tests/
│   ├── unit/                     # pruebas unitarias por módulo
│   ├── sim/                      # simulador del applet PKI del DNIe v2
│   ├── support/                  # PKI, TSA y TSL de pruebas, PDF mínimo, tarjetas simuladas
│   ├── data/                     # datos reales públicos (TSL de INDECOPI y CRL de su firmante)
│   ├── hil/                      # hardware real: pytest -m hil (sin PIN) y scripts con PIN
│   ├── interop/                  # matriz PAdES contra un validador externo (DSS 6.2)
│   └── integration/, fuzz/       # (previstos)
├── spikes/                       # prototipos de la Fase 0 (no es código de producto)
├── nautilus/                     # (previsto, Fase 5)
├── debian/                       # (previsto, Fase 5)
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

La interfaz necesita además `meson ninja-build blueprint-compiler libglib2.0-bin libglib2.0-dev-bin gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-poppler-0.18 python3-gi` y, para sus pruebas sin escritorio, `xvfb`. Para lanzarla desde el árbol de trabajo: `scripts/ejecutar.sh [archivo.pdf]`, que compila las vistas en `build/meson` y guarda las preferencias en dconf como el programa instalado. Al añadir un archivo al paquete `berigna` hay que reconfigurar Meson (`meson setup --reconfigure build/meson`), porque la lista se lee al configurar.

Comprobaciones antes de cada commit:

```bash
.venv/bin/ruff format --check src tests && .venv/bin/ruff check src tests
.venv/bin/mypy
.venv/bin/pytest --cov=berigna
```

El script `scripts/verificar.sh` ejecuta exactamente esas comprobaciones (nunca las pruebas HIL), la comprobación de la documentación (`scripts/verificar-documentacion.py`, R-DES-05) y la compilación de los catálogos con `scripts/traducciones.sh compilar` (necesita el paquete `gettext`). Las pruebas del informe PDF necesitan `poppler-utils` (`pdftotext`) y usan la fuente DejaVu (`fonts-dejavu-core`); la TSL y el informe, `python3-lxml`, `python3-signxml` y `python3-reportlab`; la verificación independiente de XAdES, el paquete `xmlsec1`. Tras añadir o cambiar un texto traducible: `scripts/traducciones.sh actualizar`, traducir la entrada en `po/es_PE.po` y dejarla en `po/quz.po` para los traductores; una prueba comprueba que `po/berigna.pot` está al día. El *hook* de `pre-push` va versionado en `scripts/hooks/` (R-DES-06): se activa una vez por clon con `git config core.hooksPath scripts/hooks`.

## 3. Estilo de código

| Aspecto | Norma |
|---|---|
| Formato y *lint* | `ruff format` y `ruff check` (incluidas las reglas de seguridad `S`) |
| Tipos | `mypy --strict` en `berigna.core`; en `ui`, modo normal |
| Nombres | Código e identificadores en inglés |
| Cadenas de la interfaz | Texto fuente en inglés (en_US) dentro de `_()`, con comentarios para traductores (`# Translators:`) cuando el contexto no sea obvio. Toda cadena nueva debe llegar con su traducción a `po/es_PE.po` en el mismo PR y con su entrada en `po/quz.po`, traducida o marcada como pendiente para los traductores; una entrada pendiente bloquea la publicación de una versión (ADR-0011, ADR-0015). Nada de concatenar frases: se usan marcadores con nombre (`_("Signed by {name}").format(name=…)`) y `ngettext` para los plurales |
| Configuración regional en desarrollo | Generar `es_PE.UTF-8` y `quz_PE` con `sudo dpkg-reconfigure locales` para poder probar ambos idiomas; las pruebas automáticas no dependen de que estén generadas. Herramientas: paquete `gettext` (`msgfmt`, `xgettext`) |
| Comentarios y *docstrings* | En inglés. La documentación de producto, en español |
| Cabeceras | `# SPDX-License-Identifier: GPL-3.0-or-later` y `# SPDX-FileCopyrightText: <año> noggalito` |
| Errores | Jerarquía `BerignaError` con un código (`ERR-xxx`) vinculado al catálogo de mensajes de UX |
| Fronteras con bibliotecas | Toda llamada a pyHanko, pyhanko-certvalidator, asn1crypto, pyscard, lxml o signxml que procese datos de fuera (un PDF, un CMS, una respuesta de red, la tarjeta) traduce sus excepciones a `BerignaError` o a un resultado ETSI, y tiene una prueba con una entrada hostil o una excepción inesperada simulada. Un documento malformado da TOTAL-FAILED/FORMAT_FAILURE o ERR-304, nunca "error inesperado"; en un lote, ni siquiera un error desconocido detiene a los demás documentos (ERR-000 en ese archivo) |
| Prototipos | `spikes/` se conserva como se escribió en la Fase 0 y queda fuera de `ruff` (`extend-exclude`); no se importa desde `src/` ni desde `tests/` |
| Registros | El módulo `logging`, con un filtro que elimina los tipos sensibles (`Pin`, `bytes` del documento) |

## 4. Flujo de trabajo con git

- Rama principal `main`, siempre publicable. Ramas `feat/…`, `fix/…`, `docs/…`.
- Commits según Conventional Commits, con DCO (`Signed-off-by`).
- Excepción: los PR de Dependabot, que solo actualizan las *actions* de GitHub (`.github/dependabot.yml`), se fusionan con el commit del bot, sin firma SSH ni `Signed-off-by`; el commit de fusión es del titular. Antes de fusionar, el PR se pone al día con `main` (`@dependabot rebase`, o `@dependabot recreate` si alguien más tocó la rama) y pasa la CI (decisión del titular, 2026-11-03).
- Toda integración en `main` pasa por una revisión y por la CI en verde.
- Los cambios que afectan a `core/token`, `core/formats`, `core/trust` o a la seguridad requieren una revisión adicional y una entrada en el registro de cambios de seguridad.

## 5. Integración continua

Estado (2026-10-28): GitHub Actions ejecuta `scripts/verificar.sh` (`.github/workflows/verificar.yml`) en cada PR y en cada *push* a `main`, dentro de un contenedor `debian:trixie` con los paquetes Python de Debian; de PyPI solo vienen pyHanko 0.25.1 (sin dependencias) y las herramientas de desarrollo, con las mismas versiones que el entorno local (§2.1). Desde la Fase 3 también compila las vistas con Meson y prueba la aplicación real con Xvfb. Cubre el paso 1 y las pruebas unitarias del paso 2; faltan SoftHSM (aplazado con el *backend* PKCS#11 a la versión 1.1), DSS (hoy con los *scripts* de `tests/interop/`) y el *fuzzing*.

Desde el 2026-11-02 (Fase 4, incremento 7), las dos CI preparan el mismo entorno con `scripts/ci-entorno.sh`, y la de cada PR además:

- genera la lista de componentes (`scripts/sbom.py`, CycloneDX 1.6) con lo que instaló y la guarda con la ejecución como artefacto `sbom` (R-DES-03). Contiene las dependencias Python de ejecución (las de `pyproject.toml` y las suyas, sin extras ni herramientas de desarrollo), con el paquete de Debian que las instaló cuando viene de Debian, los componentes de sistema del `Depends` previsto (BRG-DSP-001) y las fuentes incluidas;
- mide el rendimiento con la tarjeta simulada (`scripts/rendimiento.py`, R-DES-10): firmar un PDF de 10 MB, un lote de 20 PDF, verificar un PDF B-LTA y leer una carpeta de 200 PDF de 200 kB. Cada tiempo se divide por una carga de calibración medida en la misma máquina, y se compara con `tests/data/rendimiento/referencia.json`; si una medida es más de un 50 % más lenta, la CI deja un aviso, nunca un fallo. La referencia se rehace con `--actualizar` cuando un cambio justifica el nuevo tiempo.

La vigilancia semanal (`.github/workflows/vigilancia.yml`, BRG-MAN-001 §5, R-DES-01) corre los lunes y no bloquea ningún PR:

- `scripts/verificar.sh` completo en Debian 13 (*stable*) y en *testing* (forky). *Testing* no abre incidencias: desde el 2026-11-02 su `python3-pyhanko-certvalidator` 0.30.2 rompe pyHanko 0.25.1 al importarlo (`pyhanko_certvalidator._asyncio_compat` ya no existe), y *testing* no trae pyHanko. Es el coste conocido de Debian 14 (R-15): habrá que empaquetar una pyHanko más nueva, y lo mide el trabajo siguiente;
- `scripts/vigilar-servicios.py`: la TSL de INDECOPI (descarga, firma y días hasta su NextUpdate, aviso con menos de 7), cada espejo de las ARL de las CA del almacén (firma de su CA y vigencia), el OCSP de RENIEC y las vulnerabilidades publicadas en OSV de lo que no viene de Debian (hoy solo pyHanko, R-DES-02);
- `scripts/vulnerabilidades-debian.py`: `debsecan` sobre los paquetes de Debian del SBOM, solo informativo (R-DES-02);
- la suite completa con la última pyHanko de PyPI y sus dependencias (R-DES-08). Mide cuánto costará salir de la 0.25.1 (R-15) y nunca abre una incidencia.

Si falla Debian o un servicio, la vigilancia abre una incidencia o comenta en la que siga abierta.

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
