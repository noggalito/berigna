# Documentación técnica de berigna

| Campo | Valor |
|---|---|
| Documento | BRG-GEN-000 |
| Versión | 0.23.0 |
| Estado | Borrador |
| Fecha | 2026-11-07 |
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
│   ├── glosario-quechua.md        ← términos fijos de la traducción al quechua sureño
│   └── guia-revision-quechua.md   ← cómo revisan la traducción las personas hablantes
├── 07-calidad/
│   ├── estrategia-de-pruebas.md
│   ├── protocolo-pruebas-con-pin.md   ← obligatorio antes de usar un PIN real
│   ├── validacion-externa-fase2.md    ← matriz PAdES contrastada con DSS 6.2
│   ├── validacion-externa-fase4.md    ← matriz CAdES y XAdES contrastada con DSS 6.2
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
| 06-ux | Borrador | Interfaz implementada (Fase 3); glosario del quechua (BRG-UX-003) y guía para su revisión por hablantes (BRG-UX-004) |
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
| Otras plataformas | Windows, macOS, Android e iOS, y la lectura del DNIe por NFC, en estudio para la versión 1.1 (SPK-07); firma desde la web, también en la 1.1 (SPK-08) |

## 7. Estado de implementación (2026-11-06)

Fases 0, 1 y 2 cerradas. Fase 4: cerrada el 2026-11-04. Fase 3: funcionalmente completa (incrementos 1 a 7 hechos); su cierre formal depende de la prueba de usabilidad con al menos 5 personas (BRG-CAL-005). Los problemas de gravedad 3 y 4 que salgan de ella se corrigen antes de cerrarla. Fase 5 (escritorio y empaquetado): en curso; incrementos 1 a 4 hechos (metainfo de AppStream y entrada de escritorio; paquete `python3-pyhanko`; paquete `berigna`; extensión de Nautilus).

Fase 4 (CAdES y XAdES), iniciada el 2026-10-29 y cerrada el 2026-11-04, en ocho incrementos:

1. Registro local de fallos (R-DES-11). Hecho.
2. Firma CAdES `.p7s` y `.p7m`, de B-B a B-LTA (`core.formats.cades`; RF-020 a RF-022). Hecho: válida en DSS 6.2 (BRG-CAL-006).
3. Verificación CAdES con indicaciones ETSI (`core.validation.cades`, `verify_cades`, RF-051). Hecha: contrastada con DSS 6.2 en la matriz (BRG-CAL-006). La interfaz (CU-05) y las pruebas por propiedades llegan con los incrementos 6 y 7.
4. Firma XAdES envuelta y envolvente, de B-B a B-LTA (`core.formats.xades`; RF-030, RF-031 y RF-033); la separada (RF-032), si cabe. Hecha: las tres variantes, de B-B a B-LTA, incluida la separada, que entra en la v1.0 por decisión del titular (2026-11-01); DSS 6.2 reconoce las doce combinaciones, con TOTAL_PASSED en B-LT y B-LTA y los sellos de firma y de archivo PASSED (BRG-CAL-006 §3.3). Corregida tras la revisión del 2026-11-01: los sellos excluyen los comentarios, la transformada envuelta quita solo su firma, la envuelta sobre un documento ya firmado y el DTD se rechazan antes del PIN, la URI de la separada va codificada, y la envuelta conserva prólogo y codificación; los "documentos difíciles" (comentarios, ISO-8859-1, nombre con espacios y tildes, firma previa) entran en la matriz de DSS, y xmlsec1 verifica los resúmenes en la CI como segundo verificador.
5. Verificación XAdES (RF-052), también de las firmas de ReFirma y DSS (PR-INT-05, PR-INT-06), con pruebas por propiedades sobre XML. Hecha (`core.validation.xades`, `verify_xades`): las 36 firmas de la matriz y las 12 que genera DSS concuerdan con DSS 6.2 en la indicación principal (PR-INT-06), y una firma real de Firma Perú da TOTAL-PASSED como en DSS (PR-INT-05; ReFirma PDF no firma XML, así que en XAdES no aplica). Pruebas por propiedades sobre XML generado (ida y vuelta firma-verificación, y mutaciones) y corpus de ataques de envoltura (PR-VAL-08) (BRG-CAL-006 §3.5 a §3.7).
6. Interfaz: firmar otros archivos (CU-05, con nombre, tamaño, tipo, SHA-256 y vista de texto), verificar `.p7s`, `.p7m` y `.xml`, y lotes mixtos (RF-041). Hecha: el formato se reconoce por el contenido (`core.documents`), un solo verificador elige PAdES, CAdES o XAdES (`core.verification`) y busca o pide el archivo de una firma separada, el contenido de un `.p7m` se puede guardar, los informes JSON y PDF llevan el formato y el alcance de lo firmado, y los lotes mezclan los tres formatos con un PIN (`core.batch.sign_batch`; BRG-UX-001 §3.2, §3.4 y §3.5).
7. Práctica de desarrollo: vigilancia semanal, SBOM, CI contra la última pyHanko y medidas de rendimiento (R-DES-01 a R-DES-03, R-DES-08, R-DES-10). La comprobación de la documentación (R-DES-05) y el gancho `pre-push` (R-DES-06) ya están hechos: adelantados el 2026-11-02 por la revisión del 2026-11-01, que los echaba en falta. Hecha: vigilancia semanal en Debian *stable* y *testing* y de la TSL, las ARL y el OCSP de RENIEC (`.github/workflows/vigilancia.yml`), OSV para pyHanko y `debsecan` para Debian, SBOM CycloneDX en cada CI, la suite contra la última pyHanko y medidas de rendimiento con aviso si empeoran más de un 50 % (BRG-DES-001 §5, BRG-MAN-001 §5).
8. Matriz externa formato × nivel con DSS 6.2 y Firma Perú, y prueba con el DNIe real y PIN: el criterio de salida de la fase. Hecha (2026-11-03, PR #56 a #58):
   - la matriz simulada, repetida con el código actual, da en DSS 6.2 los mismos resultados (BRG-CAL-006 §3.9);
   - DP-20, opciones A y E, con pruebas por mutación de CAdES y PDF;
   - con el DNIe real y un PIN, las 7 variantes B-B son válidas en DSS 6.2 y en berigna; en Firma Perú, 5 de las 7 tal cual, y la `.p7m` lo es cambiando su extensión a `.p7s` (su validador web llama `.p7s` a toda CAdES y no admite `.xsig`; BRG-CAL-006 §3.10);
   - decisión del titular (2026-11-03): se mantienen los nombres estándar y berigna avisa de las diferencias con Firma Perú al elegir el formato.

   Quedan fuera del incremento: los niveles B-T a B-LTA con el DNIe real, que esperan una TSA acreditada (DP-02), y el envío de la incidencia a pyHanko (opción D de DP-20), que espera el aviso del titular.

Con el incremento 8, la Fase 4 queda cerrada el 2026-11-04.

La cofirma CAdES (RF-023, "Podría") queda para la versión 1.1 (decisión del titular, 2026-11-06).

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
| `core.validation.cades` (verificador CAdES, `verify_cades`) | Implementado (Fase 4, incremento 3): mismos procesos ETSI sobre el CMS (básico §5.3 y con sello §5.5), sello de firma y sellos de archivo `archive-time-stamp-v3` con su integridad contra el `ats-hash-index-v3` (§5.4), contenido encapsulado o dado por el llamador, datos de revocación embebidos (RFC 5940) o por el llamador | RF-051, RF-053, RF-056 | Las 8 combinaciones de la matriz contrastadas con DSS 6.2: indicación idéntica y subindicación más precisa (BRG-CAL-006 §3.3) |
| `core.validation.xades` (verificador XAdES, `verify_xades`) y `core.validation.xmldsig` (su capa XMLDSig, separada el 2026-11-07, R-DES-19) | Implementado (Fase 4, incremento 5): procesos ETSI propios sobre XMLDSig (formato, certificado firmante por `SigningCertificate(V2)`, referencias con una lista permitida de transformadas —firma envuelta, XPath Filter 2.0 `subtract`, base64 y las C14N—, valor de la firma, validación X.509 y proceso con sello §5.5), sello de firma y sellos de archivo `xades141:ArchiveTimeStamp` recalculados sobre la firma; identificadores duplicados rechazados y alcance de lo firmado en el informe (AM-06) | RF-052, RF-053, RF-056 | Las 36 firmas de la matriz y las 12 de DSS concuerdan con DSS 6.2 (BRG-CAL-006 §3.5 y §3.6); Firma Perú real: TOTAL-PASSED, como DSS (§3.7) |
| `core.i18n` y `core.report` | Implementado: catálogos gettext es_PE y quechua, completos (el quechua, traducción automática en línea sin revisar por hablantes hasta la 1.1, DP-14, ADR-0015); explicación de cada indicación y subindicación ETSI y de cada `ERR-xxx`; informes JSON y PDF, con DNI y RUC enmascarados | RF-053, RF-054, PR-I18N-04, PR-I18N-07 | Pruebas de cobertura del catálogo; informe de un PDF real revisado |
| TSA de producción | Pendiente de DP-02 (aún no hay TSA acreditada contratada) | RF-062 | — |
| Proxy y caché de la TSL | Implementado (Fase 3, incremento 4): `core.net.proxy` y `core.trust.cache` | RF-061, RF-064 | Descarga real de la TSL de INDECOPI (secuencia 25, 68 CA) y lectura desde la caché |
| `ui` (interfaz gráfica) | Fase 3, funcionalmente completa. Incremento 1: aplicación `com.noggalito.Berigna` con Meson, ventana principal, estado del DNIe, apertura de archivos (botón, arrastrar y argumentos), esquema de GSettings, cambio de idioma sin reiniciar y aviso de traducción sin revisar. Incremento 2: verificación de PDF (CU-06) con resumen, detalles técnicos, informes JSON y PDF y versión firmada. Incremento 3: firma de PDF (CU-01, CU-03) con vista previa (Poppler, ADR-0016), nivel, diálogo del PIN y documentos certificados (ERR-307). Incremento 4: Preferencias (CU-08), TSL de INDECOPI en uso con caché y proxy. Incremento 5: firma visible (CU-02) con texto, rúbrica, logotipo o QR, en horizontal o vertical. Incremento 6: lotes, diagnóstico, registro técnico, historial y certificados de confianza. Incremento 7: quechua completo. Fase 4, incremento 6: firma de otros archivos en CAdES o XAdES (CU-05) con nombre, tamaño, tipo, SHA-256 y vista de texto; verificación de `.p7s`, `.p7m`, `.xml` y `.xsig` con el archivo de una firma separada buscado o pedido, y guardado del contenido de un `.p7m` | RF-001 a RF-007, RF-010 a RF-014, RF-018, RF-020 a RF-022, RF-030 a RF-033, RF-040 a RF-045, RF-050 a RF-056, RF-060, RF-061, RF-064, RF-080, RF-082, RF-083, RF-090, RF-092 | Pruebas de la aplicación real con Xvfb, también en la CI; PDF real firmado con el DNIe verificado en línea (TOTAL-PASSED) |
| Metainfo de AppStream y entrada de escritorio | Implementado (Fase 5, incremento 1): `data/com.noggalito.Berigna.metainfo.xml.in` con nombre, resumen, descripción, palabras clave y capturas en es-PE y quz-PE, fusionada con los catálogos y validada con `appstreamcli validate`; la entrada de escritorio con los MIME de firma y XML, con los textos de respaldo en es_PE (ADR-0015) | RF-071, BRG-DSP-001 §2 y §3 | `appstreamcli validate` y `desktop-file-validate` en la CI; capturas regenerables con `scripts/capturas-metainfo.sh` (inventario visual §10) |
| `python3-pyhanko` (paquete Debian) | Implementado (Fase 5, incremento 2): pyHanko 0.25.1 contra las dependencias de Debian 13 (DP-06, ADR-0013), en `packaging/python3-pyhanko/`; compilación reproducible con `scripts/empaquetar-pyhanko.sh`, con debcraft (binarios en contenedores efímeros) o debuild (además, el paquete fuente) | SPK-05, BRG-DSP-001 §5 | `lintian --pedantic` sin errores, `piuparts` e instalación funcional en Debian 13; un aviso esperado hasta cerrar el ITP #1062808 |
| Paquete `berigna` | Implementado (Fase 5, incremento 3): `debian/` con control, rules (Meson y dh-python) y copyright (incluidas las 4 tipografías con la OFL 1.1 completa y los certificados públicos de la IOFE), fuente 3.0 (quilt), changelog y página de manual berigna(1). Decisión de las tipografías: se mantienen las copias incluidas y se justifican en `debian/copyright` (Debian trae Source Sans 3 solo en CFF, que ReportLab no incrusta, y no trae Arvo); para el archivo oficial, con el patrocinador (ADR-0020); DP-21 por abrir si se prefiere un paquete `fonts-berigna`. `scripts/empaquetar-berigna.sh` compila reproducible con debcraft o debuild | RF-071 a RF-073, ADR-0013, ADR-0018, BRG-DSP-001 §7 | `lintian --pedantic` sin errores; instalación funcional en Debian 13; RF-072 (arrastrar y soltar) y RF-073 (instancia única y apertura como argumento) verificadas con el paquete instalado |
| `core.batch` y firma por lotes en la interfaz | Implementado (Fase 3, incremento 6): un PIN por lote, lista confirmada, tolerancia a fallos, cancelación entre archivos, informe CSV (`core.report.batch_report`). Lotes mixtos desde la Fase 4, incremento 6 (`sign_batch`): PAdES, XAdES o CAdES según el contenido de cada archivo, con la variante elegida para los XML y para el resto | RF-040 a RF-043 | Tarjeta simulada: un solo VERIFY para todo el lote; pruebas de la interfaz con Xvfb |
| `core.crashes` (registro local de fallos) | Implementado (Fase 4, incremento 1): excepciones no capturadas en cualquier hilo y fallos de código nativo (`faulthandler`) al registro técnico y a un informe pendiente, con los números enmascarados; en el siguiente arranque, un aviso único con "Copiar el informe"; nada se envía solo | R-DES-11, RNF-SEG-07 | Pruebas del núcleo y de la interfaz con Xvfb |
| `core.diagnostics` y `core.logs` | Implementado (Fase 3, incremento 6): diagnóstico en orden con acción sugerida e informe copiable; registro técnico rotativo con números enmascarados | RF-007, RF-083 | Tarjeta simulada y PKI de pruebas; pruebas de la interfaz con Xvfb |
| `core.history`, historial y vista del almacén de confianza | Implementado (Fase 3, incremento 6): historial SQLite 0600 con búsqueda, CSV y borrado; certificados de confianza por origen en Preferencias | RF-060, RF-082 | Pruebas de la interfaz con firma y verificación reales (tarjeta simulada) |
| `core.formats.cades` y `core.signing.sign_cades_file` | Implementado (Fase 4, incremento 2): firma CAdES separada (`.p7s`) y envuelta (`.p7m`) de cualquier archivo, de B-B a B-LTA, con el mismo orden de seguridad que PAdES; la verificación CAdES está en `core.validation.cades` (incremento 3, contrastada con DSS 6.2) | RF-020 a RF-022 | Tarjeta simulada y TSA de pruebas: las 8 combinaciones reconocidas por DSS 6.2, B-LT y B-LTA con TOTAL_PASSED (`07-calidad/validacion-externa-fase4.md`); las 8 verificadas por `verify_cades` con la misma indicación que DSS |
| `core.formats.xades` y `core.signing.sign_xades_file` | Implementado (Fase 4, incremento 4, corregido el 2026-11-02): firma XAdES de documentos XML envuelta (la firma dentro del documento), envolvente (el documento dentro de `ds:Object`) y separada (`.xsig`, que referencia al documento por su nombre, URI codificada), de B-B a B-LTA, con signxml 4.0.5 más capa propia para T, LT y LTA (C14N 1.0 en los datos y exclusiva en `SignedInfo`, `SignedProperties` y `KeyInfo` desde el 2026-11-02, y `SigningCertificate` solo con el firmante, ADR-0008) y el mismo orden de seguridad que PAdES y CAdES; antes del PIN se rechaza lo que no se puede firmar: lo que no es XML, el DTD, un documento ya firmado en la forma envuelta y las instrucciones de procesamiento fuera de la raíz en las formas que no las cubren | RF-030 a RF-033 | Tarjeta simulada y TSA de pruebas: las doce combinaciones más los documentos difíciles de la revisión del 2026-11-01 (comentarios, ISO-8859-1, nombre con espacios y tildes, firma previa), 44 archivos con TOTAL_PASSED en B-LT y B-LTA y ningún HASH_FAILURE (`07-calidad/validacion-externa-fase4.md` §3.3); xmlsec1 verifica los resúmenes en la CI; la verificación XAdES está en `core.validation.xades` (incremento 5) |
| Extensión de Nautilus (paquete `berigna-nautilus`) | Implementado (Fase 5, incremento 4): `src/berigna_nautilus.py`, instalado en `/usr/share/nautilus-python/extensions/` con las acciones "Firmar con berigna" (archivos y carpetas; varios, o una carpeta, abren el lote, CU-04) y "Verificar firma" (un solo archivo, que berigna verifica o firma según su contenido), con las etiquetas del catálogo de berigna (ADR-0011, ADR-0015) y el icono simbólico; lanza berigna con la selección y la instancia en marcha la recibe por D-Bus (RF-073); la extensión nunca lee los archivos. Paquete binario `berigna-nautilus` (Depends: `berigna (= ${binary:Version})`, `python3-nautilus`), recomendado por `berigna` (BRG-DSP-001 §1 y §8) | RF-070, RF-073 | Pruebas del proveedor con Nautilus y Gio simulados (100 % de cobertura), con la emisión real de la señal "activate"; `lintian --pedantic` sin errores y `piuparts` PASS con los tres paquetes (BRG-DSP-001 §8); probada en GNOME real el 2026-11-06 (las dos acciones con un archivo, el lote con varios y con una carpeta); la VM del criterio de salida la repetirá desde el repositorio (incremento 6) |
| PIN pad (PC/SC parte 10) | Aplazado a la versión 1.1 (decisión del 2026-10-27; requiere un lector de clase 2) | RF-005, P-08 | — |
| *Backend* PKCS#11 + SoftHSM | Aplazado a la versión 1.1 (decisión del 2026-10-27; el DNIe v2 no lo necesita) | ADR-0003 | — |
| DNIe 1.0 y DNIe 3.0 | Versión 1.1 (decisión del 2026-10-27); identificación pendiente en SPK-06 | RNF-COM-05 | — |
| Perfiles con nombre de la firma visible | Versión 1.1 (decisión del 2026-10-29); en la v1.0, una sola apariencia, la de Preferencias | RF-081 | — |
| Extensión de LibreOffice "Firmar con berigna" | Versión 1.2 (decisión del 2026-10-27) | RF-074 | — |
| Lectura del DNIe por NFC y teléfono (berigna en Android o el teléfono como puente) | Versión 1.1 (decisión del 2026-10-29); investigación en SPK-07 | ADR-0003, ADR-0012 | — |
| Firma desde la web: verificador web, invocador (extensión del navegador y puente nativo, con "documento completo") y compatibilidad con los sistemas integrados con Firma Perú | Versión 1.1 (decisión del 2026-11-02; antes estaba después de la 1.1); sin lector, el teléfono por NFC como puente (SPK-07); investigación en SPK-08 | ADR-0002 | — |
| Windows, macOS, Android e iOS | Versión 1.1 (decisión del 2026-10-29); el núcleo es independiente de la interfaz (ADR-0002) | ADR-0021 | — |

Verificación local: `scripts/verificar.sh` (ruff, mypy estricto, pytest con cobertura mínima del 80 %; al 2026-11-01, 100 % del núcleo y 95 % del total con 598 pruebas, incluidas las de la interfaz con Xvfb; las 5 con hardware se omiten sin `BERIGNA_HIL=1`). Pruebas con hardware: `BERIGNA_HIL=1 pytest -m hil` (sin PIN) y los *scripts* manuales de `tests/hil/` (con PIN, según el protocolo).

