# berigna

Aplicación de escritorio para GNU/Linux (Debian) que permite firmar digitalmente documentos —especialmente PDF— con los certificados digitales que trae por defecto el DNI electrónico (DNIe) peruano, y verificar documentos firmados.

> Estado: en desarrollo, Fase 3 (interfaz gráfica) funcionalmente completa; su cierre formal depende de la prueba de usabilidad con usuarios. berigna firma PDF en PAdES, de B-B a B-LTA, con el DNIe v2, también por lotes y con firma visible (las firmas son válidas en Firma Perú, el validador de referencia, y en el validador web de ReFirma), verifica firmas PAdES con indicaciones ETSI, genera informes en JSON y PDF, y está en español y en quechua. Todavía no hay versiones publicadas. Estado detallado en [`docs/README.md`](docs/README.md) §7. Los prototipos de investigación de la Fase 0 están en [`spikes/`](spikes/README.md).

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

## Por dónde empezar

1. [Índice de la documentación técnica](docs/README.md)
2. [Requisitos](docs/03-requisitos/requisitos-funcionales.md) y [arquitectura](docs/04-arquitectura/arquitectura-general.md)
3. [Investigaciones previas (spikes)](docs/10-investigacion/README.md) de la Fase 0.
4. [Entorno de desarrollo](docs/08-desarrollo/entorno-y-convenciones.md) y verificación local con `scripts/verificar.sh`.

## Licencia

berigna es software libre: puedes redistribuirlo y/o modificarlo bajo los términos de la GNU General Public License publicada por la Free Software Foundation, en su versión 3 o, a tu elección, cualquier versión posterior (SPDX: `GPL-3.0-or-later`).

Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA. Consulta la GPL para más detalles. El texto completo está en [`LICENSE`](LICENSE).

Como permiso adicional según la sección 7 de la GPL, berigna se puede distribuir por tiendas de aplicaciones aunque sus condiciones restrinjan a quien lo instala, siempre que el código fuente siga disponible bajo la GPL por otro medio ([`LICENSE-EXCEPTION.md`](LICENSE-EXCEPTION.md), ADR-0021).
