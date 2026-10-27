# Estándares técnicos

| Campo | Valor |
|---|---|
| Documento | BRG-NOR-002 |
| Versión | 0.1.1 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Estándares de firma

| Estándar | Título | Uso en berigna |
|---|---|---|
| ETSI EN 319 142-1 | PAdES: bloques de construcción y perfiles de línea base | Firma de PDF (RF-010 a RF-019) |
| ETSI EN 319 122-1 | CAdES: bloques de construcción y perfiles de línea base | Firma de cualquier archivo (RF-020 a RF-023) |
| ETSI EN 319 132-1 | XAdES: bloques de construcción y perfiles de línea base | Firma de XML (RF-030 a RF-033) |
| ETSI EN 319 102-1 | Procedimientos de creación y validación de firmas AdES | Motor de verificación (RF-050 a RF-056) |
| ETSI TS 119 102-2 | Informe de validación de firmas | Estructura del informe exportable (RF-054) |
| ETSI TS 119 172-1 | Políticas de firma | Aplicación de la política de firma de la IOFE, si existe |
| ISO 32000-1 / ISO 32000-2 | Formato PDF 1.7 / PDF 2.0 | Estructura de firmas, actualizaciones incrementales, DSS y VRI |
| ISO 19005 | PDF/A | Preservación de la conformidad PDF/A (RF-017) |
| W3C XML Signature Syntax and Processing (1.1) | XMLDSig | Base de XAdES |
| W3C Canonical XML (1.0, 1.1, Exclusive) | Canonicalización | XAdES |

## 2. Estándares de PKI

| Estándar | Título | Uso |
|---|---|---|
| RFC 5280 | Perfil X.509 de certificados y CRL | Validación de la cadena |
| RFC 6960 | OCSP | Estado de revocación en línea |
| RFC 3161 | Protocolo de sellado de tiempo (TSP) | Niveles T, LT y LTA |
| RFC 5816 | ESSCertIDv2 en TSP | Sellos con SHA-256 |
| RFC 5652 | CMS | Contenedor de CAdES y de la firma PAdES |
| RFC 5035 | ESS: SigningCertificateV2 | Atributo firmado obligatorio en la línea base |
| RFC 8017 | PKCS#1 v2.2 (RSA) | Algoritmo de firma (según lo que soporte el chip) |

## 3. Estándares de dispositivo

| Estándar | Uso |
|---|---|
| PKCS#11 v2.40 / v3.x (OASIS) | API de acceso al *token* |
| PC/SC (pcsc-lite) | Acceso al lector |
| USB CCID | Clase de lector soportada |
| ISO/IEC 7816-3/4 | Protocolo de la tarjeta de contacto (referencia para diagnóstico) |
| PKCS#15 / ISO 7816-15 | Estructura de archivos de la tarjeta; depende de lo que muestre SPK-01 |

## 4. Algoritmos criptográficos

| Elemento | Requisito | Observación |
|---|---|---|
| *Hash* del documento | SHA-256 como mínimo; SHA-384 y SHA-512 configurables | Prohibidos en firmas nuevas: MD5 y SHA-1 (guía de INDECOPI v4.0, req. 6 y anexo 1) |
| Tamaño de clave | RSA de 2048 bits como mínimo | Se rechaza firmar con RSA 1024 o menor (guía de INDECOPI v4.0, req. 6) |
| Firma | RSA PKCS#1 v1.5 con SHA-256 | Verificado en SPK-01: el DNIe v2 tiene claves RSA 2048 y aplica el relleno PKCS#1 v1.5 sobre un `DigestInfo` calculado fuera (driver APDU, ADR-0012). Con el *backend* PKCS#11 equivale a `CKM_RSA_PKCS` sobre el DigestInfo |
| Sello de tiempo | El *hash* que acepte la TSA, preferentemente SHA-256 | — |
| Verificación de firmas heredadas | Se aceptan algoritmos débiles solo con una advertencia, según las fechas de validez de algoritmos de ETSI TS 119 312 | — |

## 5. Estándares de escritorio y empaquetado

| Estándar | Uso |
|---|---|
| GNOME HIG | Diseño de la interfaz |
| freedesktop Desktop Entry, Shared MIME-info, AppStream | Integración con el escritorio |
| Debian Policy Manual, Debian Python Policy | Empaquetado `.deb` |
| XDG Base Directory | Ubicación de la configuración, la caché y los datos |
| GNU gettext / itstool | Traducción de la interfaz y del manual (es_PE y en_US) |
| BCP 47 (IETF) | Etiquetas de idioma en AppStream (`es-PE`, `en-US`) |
| Unicode CLDR / POSIX locale | Formatos regionales de fechas, horas y números |

## 6. Interpretación del perfil de línea base para berigna

| Nivel | Qué contiene | Qué necesita | Validez a largo plazo |
|---|---|---|---|
| B-B | Firma CMS/XML con atributos firmados obligatorios (certificado del firmante, *hash* y hora declarada) | Solo el DNIe | Hasta que caduque o se revoque el certificado |
| B-T | B-B más un sello de tiempo sobre la firma | TSA | Prueba la fecha de existencia, pero no incluye los datos de validación |
| B-LT | B-T más los certificados de la cadena y las respuestas OCSP o CRL embebidas (en PAdES, dentro del diccionario DSS) | TSA y OCSP o CRL según el estándar. En berigna, para el DNIe: OCSP obligatorio (la CRL de 109 MB no es viable; RF-063, SPK-02) | Verificable sin conexión mientras sigan siendo fuertes los algoritmos y el sello |
| B-LTA | B-LT más un sello de tiempo de archivo (en PAdES, un *document timestamp*) | TSA | Se puede extender indefinidamente volviendo a sellar |
