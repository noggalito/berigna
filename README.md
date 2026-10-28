# berigna

Aplicación de escritorio para GNU/Linux (Debian) que permite firmar digitalmente documentos —especialmente PDF— con los certificados digitales que trae por defecto el DNI electrónico (DNIe) peruano, y verificar documentos firmados.

> Estado: en desarrollo, Fase 2 (niveles superiores y verificación) en curso. El núcleo ya firma PDF en PAdES B-B con el DNIe v2, y esas firmas son válidas en el validador oficial Firma Perú; también verifica firmas PAdES con indicaciones ETSI; todavía no hay interfaz gráfica ni versiones publicadas. Estado detallado en [`docs/README.md`](docs/README.md) §7. Los prototipos de investigación de la Fase 0 están en [`spikes/`](spikes/README.md).

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
| Distribución | Paquete `.deb` (Fedora y otras distribuciones en la hoja de ruta) |
| Idiomas | Español del Perú (es_PE) y quechua sureño, ambos completos; inglés (en_US) en la versión 1.1 |
| Licencia | GPL-3.0-or-later |
| Titular | `{{TITULAR}}` (pendiente) |

## Por dónde empezar

1. [Índice de la documentación técnica](docs/README.md)
2. [Requisitos](docs/03-requisitos/requisitos-funcionales.md) y [arquitectura](docs/04-arquitectura/arquitectura-general.md)
3. [Investigaciones previas (spikes)](docs/10-investigacion/README.md) de la Fase 0.
4. [Entorno de desarrollo](docs/08-desarrollo/entorno-y-convenciones.md) y verificación local con `scripts/verificar.sh`.

## Licencia

berigna es software libre: puedes redistribuirlo y/o modificarlo bajo los términos de la GNU General Public License publicada por la Free Software Foundation, en su versión 3 o, a tu elección, cualquier versión posterior (SPDX: `GPL-3.0-or-later`).

Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA. Consulta la GPL para más detalles. El texto completo está en [`LICENSE`](LICENSE).
