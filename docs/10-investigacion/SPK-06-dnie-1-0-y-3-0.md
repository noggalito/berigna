# SPK-06: Identificación del DNIe 1.0 y del DNIe 3.0

| Campo | Valor |
|---|---|
| Documento | BRG-INV-006 |
| Versión | 0.1.0 |
| Estado | Pendiente (se necesita acceso a un DNIe 1.0 y a un DNIe 3.0) |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Contexto

berigna 1.0 solo reconoce el DNIe v2 (chip NXP JCOP3; SPK-01). Por decisión del titular (2026-10-27), la versión 1.1 debe soportar también:

- **DNIe 1.0** (desde 2013). Chip Oberthur con aplicación IAS-ECC, según la base de datos de `pcsc-tools` ("National ID Card of Peru issued by RENIEC from Oberthur", ATR `3B DD 18 00 81 31 FE 45 80 F9 A0 00 00 00 77 01 00 70 0A 90 00 8B`). OpenSC tiene un controlador IAS-ECC; la incidencia #1147 de OpenSC (2017) muestra su uso con este DNIe, con problemas de mecanismos de firma. Los emitidos hasta 2020 pueden seguir vigentes.
- **DNIe 3.0** (presentado el 15/04/2025; desde agosto de 2025, el único que emite RENIEC). Chip y aplicación PKI desconocidos para el proyecto. Fuentes de prensa le atribuyen lectura sin contacto, pero falta confirmarlo.

## 2. Preguntas

1. ATR de cada versión, y si hay variantes según el lote o el fabricante.
2. Qué aplicaciones responden (SELECT por AID: el PKI `E828BD080FD250 "Generic"` del DNIe v2, IAS-ECC, PKCS#15, ICAO eMRTD, gestor GlobalPlatform).
3. ¿El DNIe 3.0 usa el mismo protocolo que el v2 (mismos archivos `001B`, `001C` y `001D`, VERIFY `0x81`, MSE:SET y PSO:CDS)? Si es así, basta con añadir su ATR al driver.
4. ¿OpenSC (versión 0.26.1 de Debian y la más reciente) reconoce el DNIe 1.0 y firma con él mediante PKCS#11? Esto condiciona el *backend* PKCS#11 de la versión 1.1.
5. Emisor, cadena, políticas y algoritmo de los certificados de cada versión. ¿Siguen en ROOT 3 o pasan a ROOT 5?
6. ¿El DNIe 3.0 permite firmar sin contacto (NFC), y con qué protocolo de acceso (PACE)?

## 3. Método

Solo lectura y **sin PIN** en la fase de identificación (protocolo de PIN, regla PIN-07). Se reutilizan los prototipos de `spikes/spk01/` (`read_certs.py`, `reader_profile.py`) y `opensc-tool`/`pkcs11-tool`, con el procedimiento de SPK-01 §3.1 a §3.5. La firma con PIN, si hace falta, la ejecuta su titular con su propio DNIe y siguiendo el protocolo.

No se publica en el repositorio ningún dato personal de las tarjetas usadas (nombre, DNI, certificados del titular).

## 4. Criterio de cierre

Para cada versión: ATR, aplicaciones, ruta de firma (driver APDU o PKCS#11) y cadena de certificación documentados, con una decisión de implementación para la versión 1.1.
