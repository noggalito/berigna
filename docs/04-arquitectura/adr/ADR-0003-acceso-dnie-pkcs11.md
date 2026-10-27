# ADR-0003: Acceso al DNIe con un lector USB de contacto mediante PKCS#11

- Estado: Aceptado; modificado por [ADR-0012](ADR-0012-driver-dnie-v2-apdu-y-opensc.md). El DNIe v2 no está soportado por OpenSC, así que se accede a él con un driver APDU propio. PKCS#11 se mantiene como *backend* genérico y como destino futuro.
- Fecha: 2026-10-27

## Contexto

El titular del proyecto decidió que la v1 use lectores de tarjeta inteligente USB de contacto y que otras vías (sin contacto, móvil, remota) se exploren en la siguiente versión. Además, hay que elegir la capa de software con la que se habla con el chip.

## Decisión

1. Hardware soportado: lectores USB de clase CCID gestionados por `pcscd` + `libccid` (paquetes de Debian).
2. Capa de software: la API estándar PKCS#11, a través de la biblioteca Python `python-pkcs11`. berigna no implementa comandos APDU propios.
3. Módulo PKCS#11: configurable (clave `pkcs11-module`). Por defecto se detecta automáticamente entre una lista de módulos conocidos, empezando por `opensc-pkcs11.so`. El módulo definitivo se fija con DP-01, a partir de SPK-01.
4. Las operaciones con la clave privada se ejecutan dentro del chip (`C_Sign`). Fuera del chip solo se calcula el *hash*.

## Alternativas consideradas

- Driver APDU propio sobre PC/SC: el máximo control, pero reimplementa un middleware, requiere especificaciones del chip que podrían no ser públicas y multiplica la superficie que hay que auditar. Solo se reconsidera si no existe ningún módulo PKCS#11 viable (plan de contingencia de R-01).
- p11-kit como intermediario: se puede usar de forma transparente si el sistema lo configura. No se impone.

## Consecuencias

- Cualquier *token* PKCS#11 podría funcionar en el futuro (por ejemplo, *tokens* USB de otras entidades de certificación de la IOFE) con poco trabajo adicional.
- Si el DNIe no tiene un módulo PKCS#11 libre en Linux, el proyecto queda bloqueado hasta resolverlo. Es el riesgo principal (R-01).
- Los lectores con PIN pad se soportan mediante `CKF_PROTECTED_AUTHENTICATION_PATH`.

## Fe de erratas (2026-10-27)

- Consecuencias, PIN pad: `CKF_PROTECTED_AUTHENTICATION_PATH` aplica solo al *backend* PKCS#11. Con el driver del DNIe v2 (ADR-0012), el PIN pad se usa mediante PC/SC parte 10 (`FEATURE_VERIFY_PIN_DIRECT`), según P-08.
