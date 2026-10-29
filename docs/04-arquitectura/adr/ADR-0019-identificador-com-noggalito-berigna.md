# ADR-0019: Identificador de la aplicación `com.noggalito.Berigna`

- Estado: Aceptado
- Fecha: 2026-10-28
- Origen: DP-05 resuelta (titular: la persona jurídica noggalito, dominio `noggalito.com`)

## Contexto

El identificador de la aplicación (`application-id`) da nombre a la entrada de escritorio, a los iconos, al esquema y a la ruta de GSettings, a los recursos y a la metainfo de AppStream. Debe ser un dominio invertido que controle el titular (arquitectura general §8). El provisional, `pe.berigna.Berigna`, implicaba el dominio `berigna.pe`, que el proyecto no tiene. Flathub solo marca como verificada una aplicación si el titular demuestra que controla ese dominio, y los repositorios de AppStream lo usan como identidad estable.

## Decisión

- El identificador es `com.noggalito.Berigna`, y la ruta de GSettings y de los recursos, `/com/noggalito/Berigna/`.
- Se cambia antes de publicar ninguna versión: después, cambiarlo hace perder la configuración guardada de los usuarios y exige declarar el nombre anterior en la metainfo (`<replaces>`).

## Consecuencias

- Archivos renombrados: `data/com.noggalito.Berigna.desktop.in`, `data/com.noggalito.Berigna.gschema.xml` y `data/icons/com.noggalito.Berigna*.svg`.
- La configuración guardada durante el desarrollo bajo `/pe/berigna/Berigna/` no se migra. La integración de escritorio del árbol de trabajo se reinstala con `scripts/escritorio.sh` (borra la del identificador anterior).
- La verificación en Flathub (versión 1.1) se hará con `https://noggalito.com/.well-known/org.flathub.VerifiedApps.txt`.
