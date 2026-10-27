# ADR-0010: Meson como sistema de construcción

- Estado: Aceptado
- Fecha: 2026-10-27

## Decisión

Usar Meson, el estándar de las aplicaciones GNOME. Se encarga de compilar las vistas Blueprint, el esquema de GSettings, los recursos GResource, las traducciones (gettext), el archivo `.desktop`, la metainfo de AppStream, los iconos y la instalación de los módulos Python. El núcleo `berigna.core` mantiene además un `pyproject.toml` para desarrollo y pruebas con herramientas Python estándar.

## Consecuencias

- `debian/rules` usa `dh --buildsystem=meson`.
- El mismo `meson.build` sirve para el futuro RPM y para Flatpak.
