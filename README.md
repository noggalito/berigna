# berigna

Aplicación de escritorio para GNU/Linux (Debian) que permite firmar digitalmente documentos —especialmente PDF— con los certificados digitales que trae por defecto el DNI electrónico (DNIe) peruano, y verificar documentos firmados.

> Estado: fase de especificación. No existe todavía código de producto; los prototipos de investigación de la Fase 0 están en [`spikes/`](spikes/README.md). La definición del producto vive en [`docs/`](docs/README.md).

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
| Idiomas | Español del Perú (es_PE) e inglés (en_US), ambos completos |
| Licencia | GPL-3.0-or-later |
| Titular | `{{TITULAR}}` (pendiente) |

## Por dónde empezar

1. [Índice de la documentación técnica](docs/README.md)
2. [Requisitos](docs/03-requisitos/requisitos-funcionales.md) y [arquitectura](docs/04-arquitectura/arquitectura-general.md)
3. [Investigaciones previas (spikes)](docs/10-investigacion/README.md): el criterio de salida de la Fase 0 está cumplido (DNIe v2 identificado, firma con PIN verificada y PAdES B-B válido en el validador oficial Firma Perú; SPK-01, SPK-03). Siguen abiertas la elección de la TSA y las consultas sobre la acreditación.

## Licencia

berigna es software libre: puedes redistribuirlo y/o modificarlo bajo los términos de la GNU General Public License publicada por la Free Software Foundation, en su versión 3 o, a tu elección, cualquier versión posterior (SPDX: `GPL-3.0-or-later`).

Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA. Consulta la GPL para más detalles. El texto completo está en [`LICENSE`](LICENSE).
