# berigna

Aplicación de escritorio para GNU/Linux (Debian) que permite firmar digitalmente documentos —especialmente PDF— con los certificados digitales que trae por defecto el DNI electrónico (DNIe) peruano, y verificar documentos firmados.

> Estado: en desarrollo. Fase 4 (CAdES y XAdES) cerrada el 2026-11-04; Fase 3 (interfaz gráfica) funcionalmente completa, con el cierre formal pendiente de la prueba de usabilidad con usuarios; Fase 5 (escritorio y empaquetado) en curso, con la metainfo de AppStream, el paquete `python3-pyhanko`, el paquete `berigna` y la extensión de Nautilus ya hechos. berigna firma PDF en PAdES, de B-B a B-LTA, con el DNIe v2, también por lotes y con firma visible, y firma y verifica además CAdES (`.p7s`, `.p7m`) y XAdES (las firmas son válidas en Firma Perú, el validador de referencia, y en el validador web de ReFirma), verifica con indicaciones ETSI, genera informes en JSON y PDF, y está en español y en quechua. Versión publicada: [0.3.0](https://github.com/noggalito/berigna/releases/tag/v0.3.0) (2026-11-08), para Debian 13, todavía sin acreditar ante INDECOPI. Estado detallado en [`docs/README.md`](docs/README.md) §7. Los prototipos de investigación de la Fase 0 están en [`spikes/`](spikes/README.md).

## Resumen del producto

| Aspecto | Decisión |
|---|---|
| Plataforma objetivo v1 | Debian 13 (trixie), amd64 |
| Interfaz | Solo GUI (GTK4 + libadwaita) |
| Lenguaje | Python 3 |
| Acceso al DNIe | Lector de tarjetas inteligentes USB de contacto (PC/SC). DNIe v2: driver APDU propio (ADR-0012); otros *tokens*: PKCS#11 |
| Formatos de firma | PAdES (PDF), CAdES (cualquier archivo), XAdES (XML) |
| Niveles de firma | B-B, B-T, B-LT y B-LTA, seleccionables por el usuario |
| Funciones adicionales | Verificación de firmas, firma visible, firma por lotes, integración con Nautilus |
| Objetivo normativo | Acreditación como software de firma digital ante INDECOPI (IOFE) |
| Distribución | Paquete `.deb` en un repositorio propio y en el archivo oficial de Debian (desde la v1.0); Flatpak en la 1.1 |
| Idiomas | Español del Perú (es_PE) y quechua sureño, ambos completos; inglés (en_US) en la versión 1.1 |
| Licencia | GPL-3.0-or-later, con un permiso adicional para tiendas de aplicaciones |
| Titular | noggalito (persona jurídica) |
| Sitio y contacto | <https://berigna.noggalito.com> · `berigna@noggalito.com` |

## Instalación (Debian 13)

Descarga de la [última versión](https://github.com/noggalito/berigna/releases/latest) los paquetes `berigna` y `python3-pyhanko`, que Debian 13 no tiene, y comprueba sus sumas con `sha256sum -c --ignore-missing SHA256SUMS`. Luego:

```sh
sudo apt install ./berigna_*_all.deb ./python3-pyhanko_*_all.deb
```

`berigna-nautilus`, opcional, añade "Firmar con berigna" y "Verificar firma" al menú de Archivos. Hace falta un lector de tarjetas compatible con PC/SC y el DNIe v2 con sus certificados vigentes.

## Por dónde empezar

1. [Índice de la documentación técnica](docs/README.md)
2. [Requisitos](docs/03-requisitos/requisitos-funcionales.md) y [arquitectura](docs/04-arquitectura/arquitectura-general.md)
3. [Investigaciones previas (spikes)](docs/10-investigacion/README.md) de la Fase 0.
4. [Entorno de desarrollo](docs/08-desarrollo/entorno-y-convenciones.md) y verificación local con `scripts/verificar.sh`.

## Licencia

berigna es software libre: puedes redistribuirlo y/o modificarlo bajo los términos de la GNU General Public License publicada por la Free Software Foundation, en su versión 3 o, a tu elección, cualquier versión posterior (SPDX: `GPL-3.0-or-later`).

Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA. Consulta la GPL para más detalles. El texto completo está en [`LICENSE`](LICENSE).

Como permiso adicional según la sección 7 de la GPL, berigna se puede distribuir por tiendas de aplicaciones aunque sus condiciones restrinjan a quien lo instala, siempre que el código fuente siga disponible bajo la GPL por otro medio ([`LICENSE-EXCEPTION.md`](LICENSE-EXCEPTION.md), ADR-0021).
