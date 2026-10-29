# ADR-0020: berigna en el archivo oficial de Debian desde la v1.0

- Estado: Aceptado
- Fecha: 2026-10-28
- Origen: decisión del titular del 2026-10-28; modifica el último punto de ADR-0006

## Contexto

ADR-0006 dejaba la entrada en el archivo oficial de Debian como un objetivo a largo plazo. Estar en Debian da a berigna revisión independiente de licencias y empaquetado, el seguimiento del equipo de seguridad de Debian, la llegada automática a Ubuntu (*universe*) y a sus derivadas, y la presencia en GNOME Software sin repositorios ajenos: el archivo de Debian genera los metadatos de AppStream (DEP-11) a partir de la metainfo del paquete.

## Decisión

- El objetivo de la v1.0 estable incluye solicitar su entrada en Debian: aviso de intención de empaquetar (ITP), paquete en salsa.debian.org mantenido en el equipo de Python de Debian, revisión por un patrocinador y subida a *unstable*.
- La primera versión estable de Debian con berigna será Debian 14 (forky). Para Debian 13 se usan *trixie-backports* cuando el paquete esté en *testing*, y mientras tanto el repositorio APT propio de ADR-0006.
- El repositorio APT propio se mantiene en paralelo durante la v1: es el que llega antes a los usuarios de Debian 13 y el que admite versiones de corrección sin esperar a Debian.

## Requisitos previos

1. pyHanko en Debian (`python3-pyhanko`): hoy no está (SPK-05, ADR-0013). Hay que empaquetarlo y subirlo antes que berigna, comprobando primero si alguien ya lo ha solicitado en WNPP.
2. Tipografías del sello (ADR-0018): Debian desaconseja las copias incluidas de tipografías que ya empaqueta. Source Sans 3 está en `fonts-adobe-sourcesans3`, pero en OpenType CFF, que ReportLab no incrusta; Arvo no está en Debian. Opciones: empaquetar `fonts-arvo` y una variante TrueType de Source Sans 3, o justificar la copia en `debian/copyright` y en un *override* de lintian. Se decide con el patrocinador.
3. Metainfo de AppStream (`com.noggalito.Berigna.metainfo.xml`) válida con `appstreamcli validate`, con capturas, notas de versión y clasificación OARS.
4. Pruebas sin red y sin hardware en `autopkgtest` (las de `scripts/verificar.sh` ya lo cumplen: usan una PKI, una TSA y una tarjeta simuladas).
5. `debian/copyright` completo (tipografías, almacén de confianza, marca) y compilación reproducible.
6. Una persona que responda a los errores críticos de Debian (RC) en pocos días, y un patrocinador comprometido (Developer de Debian) mientras nadie del proyecto lo sea. Las subidas requieren una clave OpenPGP personal.

## Consecuencias

- La versión de Debian estable solo recibe correcciones aprobadas por el equipo de publicación: las versiones nuevas llegan por *backports*. Los cambios de confianza (raíces, TSL) se proponen como actualizaciones estables, como hace `ca-certificates`.
- Debian 14 entrará en congelación previsiblemente durante 2027 [VERIFICAR]: berigna y pyHanko deben estar en *testing* antes.
- Las dependencias de la v1 deben estar todas en Debian; ninguna puede venir de PyPI.
