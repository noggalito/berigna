# ADR-0008: Bibliotecas para CAdES y XAdES

- Estado: Aceptado (2026-10-27): opción A, validada en SPK-03
- Fecha: 2026-10-27

## Contexto

Las firmas CAdES y XAdES deben cubrir B-B a B-LTA, tanto al firmar con PKCS#11 como al validar. En Python la madurez es desigual entre los dos formatos.

## Propuesta

### CAdES

Usar la API CMS de pyHanko (`pyhanko.sign.signers` con datos genéricos) para B-B y B-T (el sello de tiempo va como atributo no firmado `signature-time-stamp`). Para B-LT y B-LTA, se añaden los atributos de validación y de archivo construidos con asn1crypto, siguiendo ETSI EN 319 122-1, sobre una capa propia y delgada (`core.formats.cades`).

### XAdES

| Opción | Descripción | Riesgo |
|---|---|---|
| A | `signxml` (Apache-2.0), que incluye soporte XAdES, más extensiones propias para T, LT y LTA, con un firmante que delega en PKCS#11 | Medio: hay que verificar la cobertura de los niveles y si el firmante se puede delegar en PKCS#11 |
| B | Implementación propia sobre `lxml` y `cryptography` (canonicalización C14N, referencias, `QualifyingProperties`) | Alto: mucho código criptográfico de formato propio |
| C | DSS (Java) como validador auxiliar, solo para la verificación | Contradice ADR-0001; añade una JVM |

Dato de SPK-05: `python3-signxml` 4.0.5 está en Debian 13, lo que favorece la opción A. El firmante deberá delegar en el driver APDU del DNIe v2 (ADR-0012), no en PKCS#11.

Recomendación preliminar: opción A, si SPK-03 confirma que es viable. Si no lo es, opción B con un alcance limitado y una auditoría externa.

## Criterios de aceptación de la decisión

1. Firma con un *token* PKCS#11 (SoftHSM) sin exportar la clave.
2. Genera los niveles B-B a B-LTA, validados por DSS.
3. Valida firmas XAdES producidas por ReFirma y por DSS.
4. Licencia compatible con GPL-3.0.

## Resolución (2026-10-27)

SPK-03 validó la opción A con DSS 6.2: CAdES (separada y envuelta) y XAdES (envuelta y envolvente) dan TOTAL_PASSED de B-B a B-LTA, con todos los sellos de tiempo verificados uno a uno, firmando a través de un "token" que imita el DNIe v2. Código propio: B-LT y B-LTA de CAdES (`ats-hash-index-v3` y `archive-time-stamp-v3`) y B-T, B-LT y B-LTA de XAdES (unas 150 líneas de prototipo). Reglas obligatorias:

- XAdES: `c14n_algorithm` = C14N 1.0 inclusiva; `SigningCertificate` solo con el certificado del firmante.
- CAdES B-LTA: `hashIndAlgorithm` codificado de forma explícita en `ats-hash-index-v3`.
- B-LT con el DNIe: embeber respuestas OCSP, no CRL (SPK-02).

## Fe de erratas (2026-10-27)

- Opción A: donde dice "un firmante que delega en PKCS#11", debe entenderse "un firmante que delega en el *token* a través de `TokenSigner`". Para el DNIe v2 es el driver APDU (ADR-0012); para otros *tokens*, PKCS#11.
- Criterio de aceptación 1: donde dice "Firma con un *token* PKCS#11 (SoftHSM)", debe entenderse "Firma a través de un *token* sin exportar la clave". SPK-03 usó un *token* simulado con la misma interfaz que el *applet* del DNIe v2 y después el DNIe real (SPK-03 §2 y §7).
- Criterio de aceptación 3 (validar XAdES producidas por ReFirma y por DSS): sigue pendiente (PR-INT-05, PR-INT-06); la aceptación se basó en los criterios 1, 2 y 4.
- Cobertura validada: la matriz final de SPK-03 es de 20 de 20 firmas, con XAdES envuelta y envolvente de B-B a B-LTA.
