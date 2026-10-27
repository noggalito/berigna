# ADR-0007: Niveles de firma seleccionables por el usuario

- Estado: Aceptado
- Fecha: 2026-10-27

## Contexto

La v1 debe soportar hasta B-LTA, pero el usuario debe poder elegir niveles inferiores, incluida la firma básica sin sello de tiempo.

## Decisión

- Los niveles B-B, B-T, B-LT y B-LTA están disponibles en los tres formatos.
- El nivel por defecto se toma de las preferencias (DP-04). Si el nivel elegido no se puede cumplir (por ejemplo, porque no hay TSA), no se baja de nivel en silencio: se informa al usuario y se le pide confirmación.
- Al elegir B-B o B-T se muestra una nota informativa sobre la validez a largo plazo. No se muestra ningún mensaje que lo desaconseje como si fuera un error.
- El nivel efectivamente obtenido queda registrado en el historial y aparece en la pantalla de resultado.

## Consecuencias

- La interfaz necesita un selector de nivel con explicaciones breves (ver 06-ux).
- El banco de pruebas debe cubrir la matriz completa de formato × nivel (07-calidad).
