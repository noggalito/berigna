# ADR-0002: Solo GUI con GTK4 + libadwaita, y un núcleo separado

- Estado: Aceptado
- Fecha: 2026-10-27

## Contexto

La v1 tiene una sola interfaz pública: la gráfica. El público objetivo usa principalmente Debian con GNOME. La hoja de ruta incluye una CLI y un invocador web.

## Decisión

- La GUI se construye con GTK4 + libadwaita mediante PyGObject. Las vistas se definen con Blueprint (`.blp`), que se compila a GtkBuilder `.ui`.
- Toda la lógica vive en `berigna.core`, que no depende de GTK (RNF-MAN-01). La GUI es una capa delgada.
- No se expone ninguna CLI pública en la v1. El ejecutable solo acepta rutas de archivos como argumentos (para "Abrir con" y Nautilus) y opciones estándar de GApplication.

## Alternativas consideradas

- Qt (PySide6): buena en KDE, pero menos coherente con GNOME y una dependencia adicional grande.
- Interfaz web local (Electron o un servidor local): mayor superficie de ataque y menos integración nativa.

## Consecuencias

- Aspecto nativo en GNOME, con soporte de accesibilidad (AT-SPI) y modo oscuro sin trabajo adicional.
- En otros escritorios la apariencia es GNOME, pero la aplicación es plenamente funcional.
- Añadir la CLI en la versión 1.4 solo exige un nuevo punto de entrada sobre el núcleo existente.
