# ADR-0012: Driver APDU propio para el DNIe v2 y contribución a OpenSC

- Estado: Aceptado
- Fecha: 2026-10-27
- Origen: DP-01, a partir de SPK-01
- Modifica: ADR-0003 (deja de ser cierto que berigna "no implementa comandos APDU propios")

## Contexto

SPK-01 comprobó que el DNIe v2 (chip NXP JCOP3, ATR `3B DC 18 FF 81 91 FE 1F C3 80 73 C8 21 13 66 05 03 63 51 00 02 50`) no está soportado por OpenSC 0.26.1 ni, según sus notas de versión, por la 0.27.1. Tampoco se encontró un módulo PKCS#11 de RENIEC para Linux. En cambio, el protocolo del *applet* PKI es ISO 7816-4 estándar y sencillo: seleccionar el *applet*, leer los certificados, VERIFY del PIN, MSE:SET y PSO:CDS. Hay una implementación de referencia con licencia MIT (peru-dnie).

## Decisión

Se trabaja en dos líneas en paralelo:

1. Driver APDU en Python dentro de berigna (`berigna.core.token.dnie_v2`), sobre PC/SC con `python3-pyscard` (disponible en Debian 13). Implementa la misma interfaz `TokenSigner` que el *backend* PKCS#11, de modo que el resto del núcleo no distingue entre ambos.
2. Contribución de un driver a OpenSC (en C, *upstream*) para el DNIe v2. Cuando una versión de OpenSC con ese driver llegue a las distribuciones objetivo, el *backend* PKCS#11 pasa a ser el preferente y el driver Python queda como respaldo.

El *backend* PKCS#11 genérico (ADR-0003, `python-pkcs11`) se mantiene para otros *tokens* y para el DNIe v1 (Oberthur), que OpenSC ya soporta mediante IAS-ECC. `[VERIFICAR]` el DNIe v1 con una tarjeta real.

Selección del *backend*: se decide por el ATR. Los ATR conocidos del DNIe v2 (contacto, y NFC en el futuro) usan `dnie_v2`; el resto usa PKCS#11. La clave `pkcs11-module` sigue siendo configurable.

## Reglas para el driver APDU

- La clave privada sigue sin salir del chip (RNF-SEG-01 y ACR-03 se cumplen igual): fuera de la tarjeta solo se calcula el `DigestInfo`.
- Lista blanca de instrucciones: SELECT, READ BINARY, VERIFY, MSE:SET y PSO:CDS. Cualquier otra instrucción se rechaza en el código. No hay comandos de cambio de PIN, de gestión ni de GlobalPlatform.
- El VERIFY solo se envía como respuesta a una acción explícita del usuario y nunca se reintenta automáticamente (P-06).
- Soporte de PIN pad mediante las funciones PC/SC v2 parte 10 (`FEATURE_VERIFY_PIN_DIRECT` vía `SCardControl`), si el lector las anuncia.
- Conexión con `SCARD_SHARE_EXCLUSIVE` desde antes del VERIFY hasta el cierre de la sesión, para que ningún otro proceso use la sesión autenticada (AM-01).
- Cierre de sesión obligatorio con `SCardDisconnect(SCARD_UNPOWER_CARD)` o `SCARD_RESET_CARD`, también ante errores y cancelaciones (`finally`) y al cerrar la aplicación. Nunca `SCARD_LEAVE_CARD`. Motivo: en el DNIe v2 la autenticación sobrevive a varias firmas y a volver a seleccionar el *applet*; solo se pierde con un reinicio de la tarjeta (SPK-01 §8.6).
- El driver se prueba con un simulador de tarjeta (respuestas grabadas) en CI, y con el DNIe real en las pruebas HIL.

## Alternativas consideradas

- Solo driver Python: se descartó porque deja el DNIe v2 fuera del ecosistema PKCS#11 (Firefox, LibreOffice, otras herramientas).
- Solo driver en OpenSC: se descartó porque bloquea el proyecto hasta que el driver se acepte y se distribuya.

## Consecuencias

- Se añade al proyecto un componente crítico propio (el driver APDU), que debe pasar una revisión de seguridad y formará parte del alcance de la acreditación.
- `python3-pyscard` pasa a ser una dependencia (Debian 13: 2.2.2).
- La línea de OpenSC es una tarea en paralelo de la hoja de ruta, sin bloquear la v1.0.
- El atributo `CKA_ALWAYS_AUTHENTICATE` no aplica al driver APDU. Comprobado: el VERIFY persiste entre varias PSO:CDS, así que un lote con un único PIN es viable (SPK-01 §8.6).
