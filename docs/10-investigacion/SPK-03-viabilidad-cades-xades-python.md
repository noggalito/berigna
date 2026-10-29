# SPK-03: Viabilidad de CAdES y XAdES en Python con un *token*

| Campo | Valor |
|---|---|
| Documento | BRG-INV-003 |
| Versión | 0.2.1 |
| Estado | Cerrado (2026-10-27): PKI de pruebas y DNIe real |
| Fecha | 2026-10-28 |
| Responsable | noggalito |

## 1. Preguntas

1. ¿Puede pyHanko generar CMS separados y envueltos que un validador conforme a ETSI reconozca como CAdES B-B y B-T, firmando con un *token*?
2. ¿Cuánto código propio hace falta para B-LT y B-LTA en CAdES?
3. ¿Soporta signxml la firma XAdES con una clave que no se puede exportar? ¿Qué niveles genera de forma nativa?
4. ¿Qué hace falta para XAdES T, LT y LTA?

## 2. Entorno (exactamente el de Debian 13, más pyHanko 0.25.1, según ADR-0013)

| Componente | Versión | Origen |
|---|---|---|
| pyHanko | 0.25.1 | Wheel de PyPI (SHA-256 `045a0999…4c33c`) |
| pyhanko-certvalidator | 0.26.3 | Debian 13 |
| signxml | 4.0.5 | Debian 13 |
| cryptography / asn1crypto / lxml | 43.0.0 / 1.5.1 / 5.4.0 | Debian 13 |
| Validador de referencia | DSS 6.2 (JAR oficiales de Maven Central) en un arnés Java mínimo, sobre OpenJDK 21 | Local, sin Docker ni imágenes de terceros |
| PKI de pruebas | Raíz → intermedia → firmante (no repudio), raíz → TSA. CRL y AIA servidas por HTTP local | Generada por `spk03_pki.py` |
| "Token" | Objeto que, como el DNIe v2, recibe un *hash* SHA-256 y devuelve la firma PKCS#1 v1.5 | `TokenLike` |
| TSA | TSA de pruebas en proceso (`DummyTimeStamper` de pyHanko) | Local |

## 3. Resultados: matriz validada con DSS 6.2

Se considera que una firma pasa solo si la indicación global es TOTAL_PASSED **y** cada sello de tiempo, validado de forma individual, da PASSED (ver §5, aprendizaje 1).

| Formato | B-B | B-T | B-LT | B-LTA |
|---|---|---|---|---|
| CAdES separada (`.p7s`) | ✔ | ✔ | ✔ | ✔ (sello de firma y de archivo PASSED) |
| CAdES envuelta (`.p7m`) | ✔ | ✔ | ✔ | ✔ (sello de firma y de archivo PASSED) |
| XAdES envuelta (*enveloped*) | ✔ | ✔ | ✔ | ✔ (sello de firma y de archivo PASSED) |
| XAdES envolvente (*enveloping*) | ✔ | ✔ | ✔ | ✔ (sello de firma y de archivo PASSED) |
| XAdES separada (*detached*) | No probada | | | |
| PAdES (complemento, ADR-0004) | ✔ | ✔ | ✔ | ✔ (sello de firma y de documento PASSED) |

20 de 20 archivos con TOTAL_PASSED y todos sus sellos PASSED (XAdES envolvente B-T y B-LT añadidas el 2026-10-27). DSS identificó en cada caso el nivel exacto (`CAdES-BASELINE-LTA`, `XAdES-BASELINE-LT`, etc.). Todas las firmas se hicieron con una sola operación de "token" por firma, que es el contrato del driver del DNIe v2 (ADR-0012).

## 4. Qué aporta cada biblioteca y qué es código propio

| Formato y nivel | Biblioteca | Código propio necesario | Tamaño aproximado del prototipo |
|---|---|---|---|
| CAdES B-B, B-T | pyHanko `sign_general_data(use_cades=True, timestamper=…)` | Ninguno, salvo el `Signer` que delega en el token | — |
| CAdES B-LT | — | Añadir la cadena y la información de revocación a `SignedData.certificates` y `crls` | Unas 15 líneas |
| CAdES B-LTA | — | `archive-time-stamp-v3` con `ats-hash-index-v3` (EN 319 122-1 §5.5.2 y §5.5.3) | Unas 45 líneas |
| XAdES B-B | signxml `XAdESSigner` con una clave "*duck-typed*" que delega en el token | Ninguno | — |
| XAdES B-T | — | `SignatureTimeStamp` sobre C14N(`ds:SignatureValue`) | Unas 15 líneas |
| XAdES B-LT | — | `CertificateValues` y `RevocationValues` | Unas 15 líneas |
| XAdES B-LTA | — | `xades141:ArchiveTimeStamp` (EN 319 132-1, caso no distribuido) | Unas 35 líneas |
| PAdES B-B a B-LTA | pyHanko (nativo) | Ninguno | — |

Conclusión: es viable. El código propio es acotado (unas 150 líneas de prototipo) y está concentrado en `core.formats.cades` y `core.formats.xades`, como preveía ADR-0008 (opción A).

## 5. Aprendizajes

1. **Falsos positivos en la validación global.** Con una primera implementación incorrecta del sello de archivo, DSS devolvía TOTAL_PASSED porque los datos B-LT bastaban para validar en ese momento, pero el sello de archivo daba `HASH_FAILURE`. Consecuencias:
   - las pruebas de interoperabilidad deben comprobar cada sello por separado (07-calidad);
   - el verificador de berigna debe informar del estado de cada sello, no solo del resultado global (RF-053).
2. **Huella de ATSv3 (CAdES).** Se concatenan el `eContentType`, **el *hash*** (no los bytes) de los datos firmados, los campos del `SignerInfo` y el `ATSHashIndexV3`. El `hashIndAlgorithm` debe codificarse de forma explícita, aunque en DER sea el valor por defecto, porque DSS y BouncyCastle reconstruyen el índice con ese campo presente.
3. **Canonicalización en XAdES.** Una referencia sin `Transforms` (como la de `SignedProperties`) se canonicaliza con C14N 1.0 inclusiva según XMLDSig. signxml usa el algoritmo configurado, así que berigna debe configurar `c14n_algorithm = C14N 1.0` (o añadir un `Transform` explícito) para no generar firmas que otros validadores rechacen.
4. **Sello de archivo XAdES 1.4.1.** Incluye todos los `ds:Object` salvo el de `QualifyingProperties`, también los referenciados. La exclusión de los referenciados solo aplica al `ArchiveTimeStamp` antiguo de XAdES 1.3.2.
5. **signxml añade toda la cadena a `SigningCertificate`** si se le pasa la cadena completa, y DSS lo advierte. Hay que pasarle solo el certificado del firmante; los intermedios se obtienen por AIA, que el DNIe tiene, o se embeben en `CertificateValues` en B-LT.
6. **Firmas del Estado sin sello de tiempo** (validadas con este arnés): las del Despacho Presidencial dan `INDETERMINATE / OUT_OF_BOUNDS_NO_POE` porque el certificado ya caducó y no hay sello que pruebe la fecha. Es un ejemplo real del valor de B-T y B-LT.
7. **Dos jerarquías del Estado:** ROOT 3 (DNIe, CA Class 2 II) y ROOT 5 (ECEP-RENIEC CA ROOT 5 → CA Class 3, personas jurídicas). El almacén de confianza necesita ambas.
8. **DSS se puede usar en local sin Docker:** los JAR oficiales están en Maven Central. El arnés mínimo sirve como validador de referencia en la CI (07-calidad).

## 6. Decisión resultante

ADR-0008 pasa a Aceptado con la opción A (pyHanko para CMS y signxml para XAdES, más una capa propia para T, LT y LTA). DP-03 queda cerrada.

## 7. Pendientes

1. Hecho (2026-10-27, lector "innovatech"): `spk03_dnie.py` generó CAdES, XAdES y PAdES B-B con el DNIe real, 3 firmas con un único PIN (PSO:CDS de 275, 274 y 278 ms). DSS 6.2 contra ECERNEP PERU CA ROOT 3 con el OCSP de RENIEC: CAdES-BASELINE-B, XAdES-BASELINE-B y PAdES-BASELINE-B, las tres TOTAL_PASSED. El PDF se validó además en el validador oficial Firma Perú (PCM, https://apps.firmaperu.gob.pe/web/validador.xhtml, "Firma Perú 1.1.0 | DSS 5.11.1") el 2026-10-27: "Resultado válido", formato PAdES_BASELINE_B, ruta de certificación titular → ECEP-RENIEC CA Class 2 II → ECEP-RENIEC → ECERNEP PERU CA ROOT 3, "Certificado raíz del firmante en TSL: Sí". El informe (con datos personales) lo conserva el titular y no se incluye en el repositorio.
2. XAdES separada (RF-032, prioridad "Debería").
3. B-LT con OCSP en CAdES y XAdES: el prototipo embebe CRL de la PKI de pruebas. Con el DNIe hay que embeber respuestas OCSP, porque la CRL pesa 109 MB (SPK-02).
4. Revisar los tamaños y la estructura definitiva al llevar el prototipo a `core.formats` (con pruebas, tipado y revisión).
