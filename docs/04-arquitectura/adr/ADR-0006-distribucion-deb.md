# ADR-0006: Distribución como paquete `.deb` para Debian 13

- Estado: Aceptado
- Fecha: 2026-10-27

## Decisión

- El formato principal de la v1 es un paquete `.deb` nativo para Debian 13 (trixie), publicado en un repositorio APT propio y firmado.
- Fedora y similares (RPM) quedan en la hoja de ruta (versión 1.2). Flatpak se evaluará entonces, por la complejidad del acceso a PC/SC desde el *sandbox*.
- La inclusión en los repositorios oficiales de Debian es un objetivo a largo plazo, no un requisito de la v1.

## Justificación

- Acceso directo a `pcscd` y al módulo PKCS#11 del sistema, sin las barreras de un *sandbox*.
- Las dependencias de sistema (GTK4, libadwaita, opensc, pcscd) vienen de Debian y reciben sus actualizaciones de seguridad.

## Consecuencias

- Las dependencias Python que falten en Debian deben empaquetarse (DP-06, SPK-05).
- El sistema de construcción y la estructura del código no deben depender de Debian, para facilitar el empaquetado RPM más adelante (ADR-0010).
