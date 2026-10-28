# Registro de decisiones de arquitectura (ADR)

| Campo | Valor |
|---|---|
| Documento | BRG-ARQ-ADR |
| Versión | 0.1.0 |
| Estado | Vivo |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

Formato: Contexto → Decisión → Alternativas consideradas → Consecuencias. Estados posibles: Propuesto, Aceptado, Reemplazado por ADR-XXXX, Rechazado.

Un ADR aceptado no se edita. Si la decisión cambia, se escribe un ADR nuevo que lo reemplaza.

| ADR | Título | Estado |
|---|---|---|
| [ADR-0001](ADR-0001-lenguaje-python.md) | Python como lenguaje del proyecto | Aceptado |
| [ADR-0002](ADR-0002-gui-gtk4-libadwaita.md) | Solo GUI con GTK4 + libadwaita, y un núcleo separado | Aceptado |
| [ADR-0003](ADR-0003-acceso-dnie-pkcs11.md) | Acceso al DNIe con un lector USB de contacto mediante PKCS#11 | Aceptado; modificado por ADR-0012 |
| [ADR-0004](ADR-0004-pyhanko-para-pades.md) | pyHanko como motor PAdES | Aceptado |
| [ADR-0005](ADR-0005-licencia-gpl3.md) | Licencia GPL-3.0-or-later | Aceptado |
| [ADR-0006](ADR-0006-distribucion-deb.md) | Distribución como paquete `.deb` para Debian 13 | Aceptado |
| [ADR-0007](ADR-0007-niveles-seleccionables.md) | Niveles de firma seleccionables por el usuario | Aceptado |
| [ADR-0008](ADR-0008-bibliotecas-cades-xades.md) | Bibliotecas para CAdES y XAdES | Aceptado |
| [ADR-0009](ADR-0009-almacen-confianza-propio.md) | Almacén de confianza propio de la IOFE | Aceptado |
| [ADR-0010](ADR-0010-sistema-de-construccion-meson.md) | Meson como sistema de construcción | Aceptado |
| [ADR-0011](ADR-0011-internacionalizacion-es-pe-en-us.md) | Internacionalización con dos idiomas, es_PE y en_US | Aceptado; modificado por ADR-0015 |
| [ADR-0012](ADR-0012-driver-dnie-v2-apdu-y-opensc.md) | Driver APDU propio para el DNIe v2 y contribución a OpenSC | Aceptado |
| [ADR-0013](ADR-0013-pyhanko-0-25-empaquetado-debian.md) | pyHanko 0.25.x empaquetado para Debian 13 | Aceptado |
| [ADR-0014](ADR-0014-tsl-indecopi-fuente-de-confianza.md) | La TSL de INDECOPI como fuente del almacén de confianza | Aceptado |
| [ADR-0015](ADR-0015-idiomas-es-pe-y-quechua-sureno.md) | Idiomas de la v1.0, español del Perú y quechua sureño | Aceptado |

## Fe de erratas

Los ADR aceptados no se editan. Las erratas detectadas después de aceptarlos se registran aquí y en una sección final del propio ADR.

| ADR | Errata | Fecha |
|---|---|---|
| ADR-0008 | Texto de la opción A ("delega en PKCS#11") y criterio de aceptación 1 ("token PKCS#11 (SoftHSM)"): la decisión vigente delega en el driver APDU del DNIe v2 (ADR-0012), y SPK-03 lo validó con un *token* simulado del *applet* del DNIe v2 | 2026-10-27 |
| ADR-0003 | Consecuencias: "Los lectores con PIN pad se soportan mediante `CKF_PROTECTED_AUTHENTICATION_PATH`" vale solo para el *backend* PKCS#11. Con el driver del DNIe v2, el PIN pad se usa mediante PC/SC parte 10 (`FEATURE_VERIFY_PIN_DIRECT`; P-08, ADR-0012) | 2026-10-27 |
