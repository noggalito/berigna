# ADR-0021: Permiso adicional de la GPL para distribuir por tiendas de aplicaciones

- Estado: Aceptado
- Fecha: 2026-10-29
- Origen: decisión del titular del 2026-10-29; complementa ADR-0005

## Contexto

El titular decidió estudiar para la versión 1.1 berigna en Windows, macOS, Android e iOS (SPK-07). Algunas tiendas imponen condiciones a quien instala una aplicación: reglas de uso, límites de dispositivos o gestión de derechos digitales. La GPLv3 prohíbe imponer restricciones adicionales a quien la recibe (secciones 6 y 10). En la App Store de Apple ese conflicto es conocido y ha llevado a retirar programas GPL. Google Play y F-Droid no lo plantean, y la Microsoft Store depende del modo de distribución.

La sección 7 de la GPLv3 permite al titular de los derechos añadir permisos adicionales. Hoy es fácil: al 2026-10-29 todo el código de berigna es de noggalito. Cuando haya contribuciones externas, añadir el permiso exigiría el acuerdo de cada contribuyente.

## Decisión

1. berigna se distribuye bajo GPL-3.0-or-later con el permiso adicional de [`LICENSE-EXCEPTION.md`](../../../LICENSE-EXCEPTION.md). El permiso deja distribuir el programa compilado por una tienda aunque sus condiciones impongan restricciones a quien lo instala, con dos condiciones:
   - el código fuente correspondiente sigue disponible bajo la GPL, gratis y por un medio distinto de la tienda;
   - no se imponen otras restricciones.
2. El texto que vale es el inglés, como el de la GPL; la traducción al español es informativa.
3. Las contribuciones se aceptan bajo los mismos términos, incluido el permiso (`CONTRIBUTING.md`).
4. Las cabeceras SPDX de los archivos no cambian: el permiso se declara una vez, para todo el proyecto, en `LICENSE-EXCEPTION.md`, el README y `CONTRIBUTING.md`.

## Alternativas consideradas

- **No hacer nada:** berigna nunca podría estar en la App Store, y el iPhone quedaría fuera de la versión móvil.
- **Acuerdo de licencia de contribuidor (CLA) para relicenciar después:** más fricción para quien contribuye y menos confianza en un proyecto que se presenta como auditable.
- **Licencia permisiva (MIT o Apache-2.0):** se pierde el *copyleft* que justifica ADR-0005.
- **Licencia dual comercial:** innecesaria para este fin y difícil de explicar.

## Consecuencias

- Nadie puede cerrar el código: el permiso solo cubre las condiciones de la tienda, nunca la obligación de ofrecer el código fuente.
- Una versión modificada puede conservar el permiso o quitarlo, a elección de quien la modifica.
- El permiso solo cubre el código de noggalito y de quienes contribuyan después. Una compilación para una tienda que incluya código GPL de terceros necesita también el permiso de esos titulares, y sus dependencias se revisan en la auditoría de licencias (Fase 6, RNF-LEG-02).
- El texto debe revisarlo un abogado antes de la primera publicación en una tienda (BRG-NOR-001, documentación interna).
