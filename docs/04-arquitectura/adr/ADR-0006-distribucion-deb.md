# ADR-0006: Distribución como paquete `.deb` para Debian 13

- Estado: Aceptado
- Fecha: 2026-10-27; modificado el 2026-10-28 (Flatpak en la 1.1; Snap y AppImage descartados)

## Decisión

- El formato principal de la v1 es un paquete `.deb` nativo para Debian 13 (trixie), publicado en un repositorio APT propio y firmado.
- Flatpak se construye además a partir de la versión 1.1 (decisión del 2026-10-28): un solo paquete para Ubuntu, Linux Mint, Fedora y otras distribuciones, con su propio GTK y libadwaita. Queda por probar el acceso a PC/SC desde el *sandbox* (`--socket=pcsc`) con el DNIe.
- Fedora y similares (RPM) quedan en la hoja de ruta (versión 1.2).
- Snap y AppImage se descartan por ahora (2026-10-28): Snap viene desactivado en Linux Mint y depende de la tienda de Canonical; AppImage obliga a incluir GTK, libadwaita y Python en el paquete y a responder de sus parches de seguridad.
- La inclusión en los repositorios oficiales de Debian es un objetivo a largo plazo, no un requisito de la v1.

## Justificación

- Acceso directo a `pcscd` y al módulo PKCS#11 del sistema, sin las barreras de un *sandbox*.
- Las dependencias de sistema (GTK4, libadwaita, opensc, pcscd) vienen de Debian y reciben sus actualizaciones de seguridad.

## Consecuencias

- Las dependencias Python que falten en Debian deben empaquetarse (DP-06, SPK-05).
- El sistema de construcción y la estructura del código no deben depender de Debian, para facilitar el empaquetado RPM más adelante (ADR-0010).
