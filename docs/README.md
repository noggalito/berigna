# Documentación técnica de berigna

| Campo | Valor |
|---|---|
| Documento | BRG-GEN-000 |
| Versión | 0.6.0 |
| Estado | Borrador |
| Fecha | 2026-10-29 |
| Responsable | noggalito |

## 1. Propósito

Esta carpeta reúne la documentación técnica pública de berigna: qué debe hacer el software, cómo está diseñado, cómo se protege, cómo se prueba, cómo se desarrolla y cómo se distribuye. Sirve a quienes contribuyen al código y a quienes lo auditan.

La gestión del proyecto (decisiones pendientes, relación con INDECOPI, RENIEC y proveedores, estrategia de acreditación, riesgos y evidencias con datos personales) se lleva en documentación interna que no se publica.

## 2. Estructura

```
docs/
├── README.md                          ← este índice
├── 00-gestion/
│   ├── convenciones-documentales.md   ← identificadores, estados, versionado
│   └── glosario.md
├── 02-marco-normativo/
│   └── estandares-tecnicos.md         ← ETSI, RFC, algoritmos, niveles de firma
├── 03-requisitos/
│   ├── requisitos-funcionales.md      ← RF-xxx
│   ├── requisitos-no-funcionales.md   ← RNF-xxx
│   └── casos-de-uso.md                ← CU-xx
├── 04-arquitectura/
│   ├── arquitectura-general.md
│   ├── flujos-de-firma-y-verificacion.md
│   ├── configuracion-y-datos.md
│   └── adr/                           ← decisiones de arquitectura ADR-xxxx
├── 05-seguridad/
│   ├── modelo-de-amenazas.md
│   └── manejo-de-pin-y-credenciales.md
├── 06-ux/
│   ├── diseno-de-interfaz.md
│   ├── inventario-visual.md       ← iconos, ilustraciones y piezas gráficas por diseñar
│   └── glosario-quechua.md        ← términos fijos de la traducción al quechua sureño
├── 07-calidad/
│   ├── estrategia-de-pruebas.md
│   ├── protocolo-pruebas-con-pin.md   ← obligatorio antes de usar un PIN real
│   ├── validacion-externa-fase2.md    ← matriz PAdES contrastada con DSS 6.2
│   └── prueba-de-usabilidad.md        ← protocolo de la prueba con al menos 5 personas
├── 08-desarrollo/
│   ├── entorno-y-convenciones.md
│   └── recomendaciones-a-futuro.md    ← mejoras de la práctica de desarrollo, por fase
├── 09-despliegue/
│   └── empaquetado-debian.md
├── 10-investigacion/                  ← spikes SPK-01, SPK-03, SPK-05, SPK-06 y SPK-07
└── 11-mantenimiento/
    └── plan-de-mantenimiento.md       ← versiones, vigilancia, seguridad y continuidad tras la v1.0
```

Los prototipos de investigación están en [`../spikes/`](../spikes/README.md).

## 3. Orden de lectura recomendado

| Perfil | Documentos |
|---|---|
| Visión general | README raíz → 03-requisitos → 04-arquitectura/arquitectura-general |
| Desarrollador | 03-requisitos → 04-arquitectura → 05-seguridad → 08-desarrollo → 07-calidad |
| Auditor | 02-marco-normativo → 03-requisitos → 04-arquitectura/adr → 05-seguridad → 07-calidad → 10-investigacion |
| Pruebas con un DNIe real | 07-calidad/protocolo-pruebas-con-pin → 10-investigacion/SPK-01 |

## 4. Identificadores de documentación interna

Algunos documentos públicos citan identificadores cuyo detalle está en la documentación interna, no publicada: decisiones de gestión (DP-NN), consultas externas (CE-NN), riesgos (R-NN), requisitos de acreditación (ACR-NN), objetivos y supuestos (OBJ-N, SUP-N), las investigaciones SPK-02 (TSA y servicios de validación) y SPK-04 (normativa y guía de acreditación), y los documentos BRG-VIS (visión y hoja de ruta), BRG-NOR-001 y BRG-NOR-003 (marco legal y acreditación) y BRG-RSG (riesgos). Las conclusiones técnicas que afectan al software están recogidas en los documentos públicos (requisitos, ADR y *spikes*).

## 5. Estado de los documentos

| Carpeta | Estado | Observación |
|---|---|---|
| 00-gestion | Borrador | — |
| 02-marco-normativo | Borrador | — |
| 03-requisitos | Borrador | Línea base para la v1.0 |
| 04-arquitectura | Borrador | ADR-0001 a ADR-0021 aceptados |
| 05-seguridad | Borrador | — |
| 06-ux | Borrador | Interfaz implementada (Fase 3); glosario del quechua (BRG-UX-003) |
| 07-calidad | Borrador | El protocolo de PIN está Vigente; protocolo de la prueba de usabilidad (BRG-CAL-005) pendiente de aplicar |
| 08-desarrollo | Borrador | Recomendaciones a futuro (BRG-DES-002) |
| 09-despliegue | Borrador | — |
| 10-investigacion | En curso | SPK-01, SPK-03 y SPK-05 cerrados; SPK-06 (DNIe 1.0 y 3.0) y SPK-07 (NFC y teléfono) pendientes |
| 11-mantenimiento | Borrador | Se aplica desde la v1.0 |

## 6. Decisiones técnicas principales

| Tema | Decisión |
|---|---|
| Interfaz | Solo GUI (GTK4 + libadwaita) en la v1; núcleo independiente de la interfaz (ADR-0002) |
| Lenguaje | Python 3 (ADR-0001) |
| Formatos y niveles | PAdES, CAdES y XAdES, de B-B a B-LTA, seleccionables por el usuario (ADR-0007, ADR-0008) |
| Acceso al DNIe v2 | Driver APDU propio sobre PC/SC; PKCS#11 para otros *tokens*; contribución de un driver a OpenSC (ADR-0003, ADR-0012) |
| Certificado para firmar | Solo el de no repudio |
| Confianza | Almacén propio con las raíces de la IOFE, ampliado en tiempo de ejecución con la TSL de INDECOPI verificada (ADR-0009, ADR-0014) |
| Nivel por defecto | B-LT si hay TSA y OCSP; si no, B-B con un aviso |
| Dependencias | Las de Debian 13 más pyHanko 0.25.1 empaquetado (ADR-0013) |
| Arquitecturas | Paquetes `Architecture: all`; amd64 con soporte oficial, arm64 sin soporte oficial |
| Idiomas | es_PE y quechua sureño completos (ADR-0011, ADR-0015); en_US en la versión 1.1 |
| Distribución | Paquete `.deb` para Debian 13 en un repositorio APT propio (ADR-0006) y entrada en el archivo oficial de Debian desde la v1.0 (ADR-0020); Flatpak en la 1.1 |
| Titular e identificador | noggalito; `com.noggalito.Berigna` (ADR-0019); contacto `berigna@noggalito.com` |
| Licencia | GPL-3.0-or-later (ADR-0005), con un permiso adicional para distribuir por tiendas de aplicaciones (ADR-0021) |
| Otras plataformas | Windows, macOS, Android e iOS, y la lectura del DNIe por NFC, en estudio para la versión 1.1 (SPK-07) |

## 7. Estado de implementación (2026-10-29)

Fases 0, 1 y 2 cerradas. Fase 3: funcionalmente completa (incrementos 1 a 7 hechos); su cierre formal depende de la prueba de usabilidad con al menos 5 personas (BRG-CAL-005), que no bloquea seguir con la Fase 4. Los problemas de gravedad 3 y 4 que salgan de ella se corrigen antes de cerrarla.

| Módulo | Estado | Requisitos | Evidencia |
|---|---|---|---|
| `core.token.dnie_v2` y `core.token.transport` | Implementado | RF-002, RF-003, RF-004, RF-005 (sin PIN pad) | Simulador, 100 % de cobertura; HIL con los lectores "Hyperion" e "innovatech", con PIN real |
| `core.token.monitor` | Implementado | RF-001, RF-002 | Sin conectarse a la tarjeta (`SCardGetStatusChange`); HIL: no interfiere con una sesión exclusiva |
| `core.trust` (almacén) | Implementado | RF-060, RF-061 | ROOT 3 y ROOT 5 verificadas; manifiesto de huellas |
| `core.trust.tsl` (TSL de INDECOPI) | Implementado: firma verificada con la raíz de INDECOPI fijada, vigencia, secuencia y CRL del firmante; las CA acreditadas amplían el almacén | RF-061, ADR-0014 | TSL real del 2026-08-10 (secuencia 25, 68 CA, ROOT 6) |
| `core.validation.preflight` | Implementado; rechaza también claves RSA de menos de 2048 bits (ACR-18) | RF-006 | PKI de pruebas; HIL en línea contra el OCSP y las ARL de RENIEC |
| `core.formats.pades` | Implementado: B-B, B-T, B-LT y B-LTA | RF-010, RF-013, RF-014 | B-B válido en Firma Perú y TOTAL_PASSED en DSS 6.2 con el DNIe real; B-T a B-LTA con tarjeta simulada y TSA de pruebas, validados con DSS 6.2; falta la prueba con PIN y una TSA acreditada |
| `core.signing` | Implementado (PDF, B-B a B-LTA) | RF-006, RF-018, RF-045 | Pruebas del orden de seguridad (TOCTOU, cancelación, no sobrescritura, nivel y TSA comprobados antes del PIN) |
| `core.net` (`fetchers`, `tsa`) | Implementado: cliente RFC 3161 con comprobación previa y plazo total; OCSP y CRL con reintento, espejos escalonados y sin CRL de certificados finales | RF-062 (sin interfaz), RF-063 | TSA HTTP local en las pruebas; DigiCert real; RENIEC real |
| `core.validation.pdf` (verificador PAdES) | Implementado: procesos de ETSI EN 319 102-1 básico (§5.3) y de validación a largo plazo (§5.6.3), sellos de firma y de documento (§5.4), validación en el pasado, datos de revocación embebidos (DSS y `revocationInfoArchival` de Adobe), cobertura y modificaciones posteriores | RF-050, RF-053, RF-055, RF-056 | Matriz B-B a B-LTA y documentos reales contrastados con DSS 6.2 (`07-calidad/validacion-externa-fase2.md`) |
| `core.i18n` y `core.report` | Implementado: catálogos gettext es_PE y quechua, completos (el quechua, traducido con IA y sin revisar por hablantes hasta la 1.1, DP-14, ADR-0015); explicación de cada indicación y subindicación ETSI y de cada `ERR-xxx`; informes JSON y PDF, con DNI y RUC enmascarados | RF-053, RF-054, PR-I18N-04, PR-I18N-07 | Pruebas de cobertura del catálogo; informe de un PDF real revisado |
| TSA de producción | Pendiente de DP-02 (aún no hay TSA acreditada contratada) | RF-062 | — |
| Proxy y caché de la TSL | Implementado (Fase 3, incremento 4): `core.net.proxy` y `core.trust.cache` | RF-061, RF-064 | Descarga real de la TSL de INDECOPI (secuencia 25, 68 CA) y lectura desde la caché |
| `ui` (interfaz gráfica) | Fase 3, funcionalmente completa. Incremento 1: aplicación `com.noggalito.Berigna` con Meson, ventana principal, estado del DNIe, apertura de archivos (botón, arrastrar y argumentos), esquema de GSettings, cambio de idioma sin reiniciar y aviso de traducción sin revisar. Incremento 2: verificación de PDF (CU-06) con resumen, detalles técnicos, informes JSON y PDF y versión firmada. Incremento 3: firma de PDF (CU-01, CU-03) con vista previa (Poppler, ADR-0016), nivel, diálogo del PIN y documentos certificados (ERR-307). Incremento 4: Preferencias (CU-08), TSL de INDECOPI en uso con caché y proxy. Incremento 5: firma visible (CU-02) con texto, rúbrica, logotipo o QR, en horizontal o vertical. Incremento 6: lotes, diagnóstico, registro técnico, historial y certificados de confianza. Incremento 7: quechua completo | RF-001 a RF-007, RF-010 a RF-014, RF-018, RF-040 a RF-045, RF-050, RF-053 a RF-056, RF-060, RF-061, RF-064, RF-080, RF-082, RF-083, RF-090, RF-092 | Pruebas de la aplicación real con Xvfb, también en la CI; PDF real firmado con el DNIe verificado en línea (TOTAL-PASSED) |
| `core.batch` y firma por lotes en la interfaz | Implementado (Fase 3, incremento 6): un PIN por lote, lista confirmada, tolerancia a fallos, cancelación entre archivos, informe CSV (`core.report.batch_report`) | RF-040 a RF-043 | Tarjeta simulada: un solo VERIFY para todo el lote; pruebas de la interfaz con Xvfb |
| `core.diagnostics` y `core.logs` | Implementado (Fase 3, incremento 6): diagnóstico en orden con acción sugerida e informe copiable; registro técnico rotativo con números enmascarados | RF-007, RF-083 | Tarjeta simulada y PKI de pruebas; pruebas de la interfaz con Xvfb |
| `core.history`, historial y vista del almacén de confianza | Implementado (Fase 3, incremento 6): historial SQLite 0600 con búsqueda, CSV y borrado; certificados de confianza por origen en Preferencias | RF-060, RF-082 | Pruebas de la interfaz con firma y verificación reales (tarjeta simulada) |
| CAdES y XAdES | Fase 4 (viabilidad probada en SPK-03) | RF-020 a RF-033 | — |
| Extensión de Nautilus y empaquetado `.deb` | Fase 5 | RF-070 a RF-073, ADR-0006, ADR-0013 | — |
| PIN pad (PC/SC parte 10) | Aplazado a la versión 1.1 (decisión del 2026-10-27; requiere un lector de clase 2) | RF-005, P-08 | — |
| *Backend* PKCS#11 + SoftHSM | Aplazado a la versión 1.1 (decisión del 2026-10-27; el DNIe v2 no lo necesita) | ADR-0003 | — |
| DNIe 1.0 y DNIe 3.0 | Versión 1.1 (decisión del 2026-10-27); identificación pendiente en SPK-06 | RNF-COM-05 | — |
| Perfiles con nombre de la firma visible | Versión 1.1 (decisión del 2026-10-29); en la v1.0, una sola apariencia, la de Preferencias | RF-081 | — |
| Extensión de LibreOffice "Firmar con berigna" | Versión 1.2 (decisión del 2026-10-27) | RF-074 | — |
| Lectura del DNIe por NFC y teléfono (berigna en Android o el teléfono como puente) | Versión 1.1 (decisión del 2026-10-29); investigación en SPK-07 | ADR-0003, ADR-0012 | — |
| Windows, macOS, Android e iOS | Versión 1.1 (decisión del 2026-10-29); el núcleo es independiente de la interfaz (ADR-0002) | ADR-0021 | — |

Verificación local: `scripts/verificar.sh` (ruff, mypy estricto, pytest con cobertura mínima del 80 %; al 2026-10-29, 100 % del núcleo y 95 % del total con 479 pruebas, incluidas las de la interfaz con Xvfb; las 5 con hardware se omiten sin `BERIGNA_HIL=1`). Pruebas con hardware: `BERIGNA_HIL=1 pytest -m hil` (sin PIN) y los *scripts* manuales de `tests/hil/` (con PIN, según el protocolo).

