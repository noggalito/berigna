# ADR-0009: Almacén de confianza propio de la IOFE

- Estado: Aceptado; complementado por [ADR-0014](ADR-0014-tsl-indecopi-fuente-de-confianza.md) (la TSL de INDECOPI verificada amplía este almacén en tiempo de ejecución)
- Fecha: 2026-10-27

## Contexto

El almacén de confianza del sistema (`ca-certificates`) está pensado para TLS y no tiene por qué contener las raíces de la IOFE. Además, mezclarlo con la validación de firmas legales abre la puerta a que se acepten como firmantes válidos certificados de otras autoridades.

## Decisión

- berigna incluye su propio almacén con las raíces y las intermedias de la IOFE, con un manifiesto de huellas y orígenes (BRG-ARQ-003 §3).
- Para validar firmas solo se usa ese almacén, más las anclas que añada el usuario de forma explícita, y estas se señalan en los informes.
- Para TLS (las conexiones a la TSA y a OCSP) se usa el almacén del sistema.

## Consecuencias

- Mantener el almacén al día forma parte del proceso de publicación de versiones.
- Hay que obtener los certificados de fuentes oficiales y documentar sus huellas (SPK-04).
