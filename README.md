# berigna

Aplicación de escritorio para GNU/Linux (Debian) que permite firmar digitalmente documentos —especialmente PDF— con los certificados digitales que trae por defecto el DNI electrónico (DNIe) peruano, y verificar documentos firmados.

> Estado: en desarrollo. Fase 4 (CAdES y XAdES) cerrada el 2026-11-04; Fase 3 (interfaz gráfica) funcionalmente completa, con el cierre formal pendiente de la prueba de usabilidad con usuarios; Fase 5 (escritorio y empaquetado) cerrada el 2026-11-09: repositorio APT de noggalito, paquete `berigna-nautilus` y prueba de salida en máquinas limpias de Debian 13 y Ubuntu 26.04 ([BRG-CAL-007](docs/07-calidad/validacion-vm-fase5.md)). berigna firma PDF en PAdES, de B-B a B-LTA, con el DNIe v2, también por lotes y con firma visible, y firma y verifica además CAdES (`.p7s`, `.p7m`) y XAdES (las firmas son válidas en Firma Perú, el validador de referencia, y en el validador web de ReFirma), verifica con indicaciones ETSI, genera informes en JSON y PDF, y está en español y en quechua. Versión publicada: [0.3.1](https://github.com/noggalito/berigna/releases/tag/v0.3.1) (2026-11-09), para Debian 13 (Ubuntu 26.04 LTS desde la v1.0), todavía sin acreditar ante INDECOPI. Estado detallado en [`docs/README.md`](docs/README.md) §7. Los prototipos de investigación de la Fase 0 están en [`spikes/`](spikes/README.md).

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

## Instalación (Debian 13 y Ubuntu 26.04)

Si `curl` no está instalado (Ubuntu no siempre lo trae): `sudo apt install -y curl`. Quien haya instalado el sistema con contraseña de root y no tenga `sudo` puede ejecutar los mismos comandos en una sesión de root (`su -`), sin `sudo`.

Desde el repositorio APT de noggalito, el mismo para toda la familia Debian:

```sh
sudo curl -fsSLo /usr/share/keyrings/noggalito-archive-keyring.asc \
  https://noggalito.com/apps/deb/noggalito-archive-keyring.asc
gpg --show-keys /usr/share/keyrings/noggalito-archive-keyring.asc
#   la huella debe ser A99859F6A32D8D5DEE5D3609CEA6BD335F594929
sudo curl -fsSLo /etc/apt/sources.list.d/noggalito.sources \
  https://noggalito.com/apps/deb/noggalito.sources
sudo apt update && sudo apt install berigna noggalito-archive-keyring
```

Desde ahí, las versiones nuevas llegan con `apt upgrade`, y `noggalito-archive-keyring` mantiene la clave al día. `berigna-nautilus`, que se instala como recomendación, añade "Firmar con berigna" y "Verificar firma" al menú de Archivos. Hace falta un lector de tarjetas compatible con PC/SC y el DNIe v2 con sus certificados vigentes.

Los paquetes también están en cada [versión publicada](https://github.com/noggalito/berigna/releases/latest), con su `SHA256SUMS`, para instalarlos a mano (`sudo apt install ./berigna_*_all.deb ./python3-pyhanko_*_all.deb`).

## Por dónde empezar

1. [Índice de la documentación técnica](docs/README.md)
2. [Requisitos](docs/03-requisitos/requisitos-funcionales.md) y [arquitectura](docs/04-arquitectura/arquitectura-general.md)
3. [Investigaciones previas (spikes)](docs/10-investigacion/README.md) de la Fase 0.
4. [Entorno de desarrollo](docs/08-desarrollo/entorno-y-convenciones.md) y verificación local con `scripts/verificar.sh`.

## Licencia

berigna es software libre: puedes redistribuirlo y/o modificarlo bajo los términos de la GNU General Public License publicada por la Free Software Foundation, en su versión 3 o, a tu elección, cualquier versión posterior (SPDX: `GPL-3.0-or-later`).

Se distribuye con la esperanza de que sea útil, pero SIN NINGUNA GARANTÍA. Consulta la GPL para más detalles. El texto completo está en [`LICENSE`](LICENSE).

Como permiso adicional según la sección 7 de la GPL, berigna se puede distribuir por tiendas de aplicaciones aunque sus condiciones restrinjan a quien lo instala, siempre que el código fuente siga disponible bajo la GPL por otro medio ([`LICENSE-EXCEPTION.md`](LICENSE-EXCEPTION.md), ADR-0021).
