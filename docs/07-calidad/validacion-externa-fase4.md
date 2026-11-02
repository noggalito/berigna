# Validación externa de la Fase 4: matriz CAdES y XAdES por niveles

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-006 |
| Versión | 0.6.0 |
| Estado | En curso |
| Fecha | 2026-11-02 |
| Responsable | noggalito |

## 1. Objetivo

Criterio de salida de la Fase 4 (hoja de ruta): la matriz completa de formato × nivel validada por un validador externo. Como en la Fase 2 (BRG-CAL-004), el validador externo es DSS 6.2, la biblioteca de referencia de la Comisión Europea en la que se basa el validador oficial Firma Perú. El documento crece con cada incremento: CAdES (incremento 2), XAdES (incremento 4) y la contrastación con la verificación propia de berigna (incrementos 3 y 5). El cierre llega en el incremento 8, con el DNIe real y PIN.

## 2. Método

1. `tests/interop/matriz_cades.py` firma un mismo archivo de texto en CAdES separada (`.p7s`) y envuelta (`.p7m`), de B-B a B-LTA, con el código de berigna, el DNIe simulado, la PKI de pruebas y una TSA de pruebas.
2. `tests/interop/matriz_xades.py` firma un mismo documento XML (`datos.xml`) en XAdES envuelta, envolvente y separada (`.xsig`, que referencia a `datos.xml`), de B-B a B-LTA, con los mismos medios.
3. `tests/interop/matriz_dss.sh` valida todos los archivos con DSS 6.2 (arnés de SPK-03), con la raíz de pruebas como única ancla. Una `.p7s` se valida contra `datos.txt` y una `.xsig` contra `datos.xml`. Las URL de revocación de la PKI de pruebas no responden, así que DSS trabaja solo con lo que la firma trae.
4. Verificación propia de berigna (incrementos 3 y 5): la misma matriz CAdES se relee con `berigna.core.validation.cades.verify_cades` (RF-051) y la XAdES con `berigna.core.validation.xades.verify_xades` (RF-052), sin red, y sus indicaciones y subindicaciones quedan junto a las de DSS. `matriz_xades.py` añade la verificación propia como última columna de su tabla.
5. Firmas de terceros (incremento 5): `tests/interop/firmas_dss.py` hace que DSS 6.2 firme el mismo documento en las tres variantes y los cuatro niveles (`brg.Sign` del arnés, con una clave de la PKI de pruebas, la TSA de pruebas por HTTP y los datos de revocación como archivos) y compara la verificación de berigna con la validación de DSS (PR-INT-06). `tests/interop/verificar_firma_peru.py` verifica una firma real de Firma Perú o ReFirma con el almacén propio y la TSL de INDECOPI, en línea (PR-INT-05); la firma y el documento quedan en la documentación interna, porque llevan los datos de una persona.

Para repetirlo: `.venv/bin/python tests/interop/matriz_cades.py DIR` y `.venv/bin/python tests/interop/matriz_xades.py DIR`, y `tests/interop/matriz_dss.sh DIR [dssval]`. El arnés se prepara con `spikes/preparar-entorno.sh`; si el sistema solo tiene el entorno de ejecución de Java 21, el JDK 8 compila `Validate.java` con las bibliotecas de DSS 6.2.

## 3. Resultados

### 3.1 CAdES (incremento 2, 2026-10-30)

| Archivo | Nivel pedido | Nivel alcanzado (berigna) | DSS 6.2 |
|---|---|---|---|
| `cades-B-B.p7s` | B-B | B-B | CAdES-BASELINE-B, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-T.p7s` | B-T | B-T | CAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-LT.p7s` | B-LT | B-LT | CAdES-BASELINE-LT, TOTAL_PASSED |
| `cades-B-LTA.p7s` | B-LTA | B-LTA | CAdES-BASELINE-LTA, TOTAL_PASSED |
| `cades-B-B.p7m` | B-B | B-B | CAdES-BASELINE-B, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-T.p7m` | B-T | B-T | CAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-LT.p7m` | B-LT | B-LT | CAdES-BASELINE-LT, TOTAL_PASSED |
| `cades-B-LTA.p7m` | B-LTA | B-LTA | CAdES-BASELINE-LTA, TOTAL_PASSED |

Conclusiones:

- DSS reconoce el nivel exacto de las ocho firmas.
- B-LT y B-LTA dan TOTAL_PASSED en las dos variantes: los certificados, la CRL y las respuestas OCSP (como `id-ri-ocsp-response`, RFC 5940) embebidos bastan, y el `archive-time-stamp-v3` con su `ats-hash-index-v3` es correcto.
- B-B y B-T no llevan datos de revocación, así que ningún validador puede dar más que INDETERMINATE sin consultar la red. Es el mismo resultado que PAdES en la Fase 2 (BRG-CAL-004 §3.1) y el esperado.
- La matriz PAdES de la Fase 2 se repitió el mismo día tras el cambio del código común: resultados idénticos.

### 3.2 Verificación propia de berigna (incremento 3, 2026-10-30)

`verify_cades` (RF-051) sobre los mismos ocho archivos, sin red — DSS repite fila por fila lo de §3.1:

| Archivo | berigna (`verify_cades`) | DSS 6.2 |
|---|---|---|
| `cades-B-B.p7s` | INDETERMINATE / TRY_LATER | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-T.p7s` | INDETERMINATE / TRY_LATER | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-LT.p7s` | TOTAL-PASSED | TOTAL_PASSED |
| `cades-B-LTA.p7s` | TOTAL-PASSED | TOTAL_PASSED |
| `cades-B-B.p7m` | INDETERMINATE / TRY_LATER | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-T.p7m` | INDETERMINATE / TRY_LATER | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `cades-B-LT.p7m` | TOTAL-PASSED | TOTAL_PASSED |
| `cades-B-LTA.p7m` | TOTAL-PASSED | TOTAL_PASSED |

Conclusiones:

- La indicación principal de berigna coincide con la de DSS 6.2 en los ocho casos.
- Los sellos de tiempo —el de firma en B-T y el de archivo en B-LTA— tienen su propia indicación aparte (§5.4): TOTAL-PASSED en los cuatro sellos de la matriz, como espera SPK-03 §5.
- Donde DSS da la subindicación genérica `CERTIFICATE_CHAIN_GENERAL_FAILURE`, berigna precisa la causa con su diagnóstico de cadena (ETSI EN 319 102-1 §5.2.6): `TRY_LATER`, porque falta información de revocación — el mismo criterio de la Fase 2 (BRG-CAL-004 §3.1).
- La verificación de B-LTA comprueba además que el sello de archivo cubre todavía las piezas del CMS (integridad del `ats-hash-index-v3`): en la matriz todo se cumple.

### 3.3 XAdES (incremento 4, 2026-11-01)

Las doce combinaciones de variante y nivel, generadas con el DNIe simulado y una TSA de pruebas y validadas con DSS 6.2 (la separada, contra `datos.xml`):

| Archivo | Nivel pedido | Nivel alcanzado (berigna) | DSS 6.2 |
|---|---|---|---|
| `xades-envuelta-B-B.xml` | B-B | B-B | XAdES-BASELINE-B, INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND |
| `xades-envuelta-B-T.xml` | B-T | B-T | XAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `xades-envuelta-B-LT.xml` | B-LT | B-LT | XAdES-BASELINE-LT, TOTAL_PASSED |
| `xades-envuelta-B-LTA.xml` | B-LTA | B-LTA | XAdES-BASELINE-LTA, TOTAL_PASSED |
| `xades-envolvente-B-B.xml` | B-B | B-B | XAdES-BASELINE-B, INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND |
| `xades-envolvente-B-T.xml` | B-T | B-T | XAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `xades-envolvente-B-LT.xml` | B-LT | B-LT | XAdES-BASELINE-LT, TOTAL_PASSED |
| `xades-envolvente-B-LTA.xml` | B-LTA | B-LTA | XAdES-BASELINE-LTA, TOTAL_PASSED |
| `xades-separada-B-B.xsig` | B-B | B-B | XAdES-BASELINE-B, INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND |
| `xades-separada-B-T.xsig` | B-T | B-T | XAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `xades-separada-B-LT.xsig` | B-LT | B-LT | XAdES-BASELINE-LT, TOTAL_PASSED |
| `xades-separada-B-LTA.xsig` | B-LTA | B-LTA | XAdES-BASELINE-LTA, TOTAL_PASSED |

Conclusiones:

- DSS reconoce el nivel exacto y la variante de las doce firmas, también la separada, que resuelve la referencia externa y valida contra `datos.xml`.
- B-LT y B-LTA dan TOTAL_PASSED en las tres variantes: los certificados de las rutas (sin las anclas) y las respuestas OCSP y la CRL embebidos en `CertificateValues` y `RevocationValues` bastan, y el `xades141:ArchiveTimeStamp` con su cobertura es correcto.
- En las B-LTA, DSS valida aparte los dos sellos en el informe detallado: `SIGNATURE_TIMESTAMP=PASSED` y `ARCHIVE_TIMESTAMP=PASSED` en las tres variantes.
- B-B y B-T no llevan datos de revocación, así que ningún validador puede dar más que INDETERMINATE sin consultar la red, con las mismas subindicaciones que CAdES (§3.1). Es el resultado esperado.
- RF-032 (XAdES separada) entra en la v1.0 por decisión del titular (2026-11-01); SPK-03 la había dejado sin probar y la matriz la cubre.

### 3.4 Documentos difíciles, tras las correcciones (2026-11-02)

La revisión del 2026-11-01 halló que las pruebas usaban un único XML sin comentarios, sin prólogo y sin firmas previas. La matriz se amplió con las correcciones de esa revisión y se validó de nuevo con DSS 6.2: 36 firmas XAdES (44 archivos con los 8 CAdES de la misma corrida):

- Un documento con comentarios dentro y fuera de la raíz y codificación ISO-8859-1, firmado en las tres variantes y los cuatro niveles; la separada viaja con un nombre con espacios y tildes (`acta de sesión.xml`) y la URI del documento va codificada por ciento. TOTAL_PASSED en B-LT y B-LTA, sin ningún HASH_FAILURE: los resúmenes y los sellos excluyen los comentarios, como XMLDSig.
- La separada sobre un documento que ya lleva una firma envuelta: la primera firma sigue siendo válida y DSS da TOTAL_PASSED en B-LT y B-LTA.
- Un documento con una instrucción de procesamiento fuera de la raíz (`<?xml-stylesheet?>`): envuelta con `Id` en la raíz y envolvente, TOTAL_PASSED en B-LT y B-LTA. La envuelta sin `Id` y la separada se rechazan antes del PIN (ERR-313): DSS da HASH_FAILURE de ellas, porque digiere el documento completo y el resumen de la referencia cubre solo el elemento raíz.
- xmlsec1 1.2.41 (Debian) verifica aparte, en la CI, los resúmenes y el valor de la firma de las tres variantes, con los comentarios dentro del documento: un verificador que no comparte código con berigna.

### 3.5 Verificación XAdES propia (incremento 5, 2026-11-02)

`verify_xades` (RF-052) sobre las 36 firmas de la matriz, sin red. La indicación principal coincide con la de DSS 6.2 en las 36: TOTAL-PASSED en las 18 B-LT y B-LTA, también las de los documentos difíciles y la separada sobre una firma, e INDETERMINATE en las 18 B-B y B-T. Las doce de siempre:

| Archivo | berigna (`verify_xades`) | DSS 6.2 |
|---|---|---|
| `xades-envuelta-B-B.xml` | INDETERMINATE / TRY_LATER | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND |
| `xades-envuelta-B-T.xml` | INDETERMINATE / TRY_LATER (sello: INDETERMINATE) | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `xades-envuelta-B-LT.xml` | TOTAL-PASSED (sello: PASSED) | TOTAL_PASSED |
| `xades-envuelta-B-LTA.xml` | TOTAL-PASSED (sellos: PASSED, PASSED) | TOTAL_PASSED |
| `xades-envolvente-B-B.xml` | INDETERMINATE / TRY_LATER | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND |
| `xades-envolvente-B-T.xml` | INDETERMINATE / TRY_LATER (sello: INDETERMINATE) | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `xades-envolvente-B-LT.xml` | TOTAL-PASSED (sello: PASSED) | TOTAL_PASSED |
| `xades-envolvente-B-LTA.xml` | TOTAL-PASSED (sellos: PASSED, PASSED) | TOTAL_PASSED |
| `xades-separada-B-B.xsig` | INDETERMINATE / TRY_LATER | INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND |
| `xades-separada-B-T.xsig` | INDETERMINATE / TRY_LATER (sello: INDETERMINATE) | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `xades-separada-B-LT.xsig` | TOTAL-PASSED (sello: PASSED) | TOTAL_PASSED |
| `xades-separada-B-LTA.xsig` | TOTAL-PASSED (sellos: PASSED, PASSED) | TOTAL_PASSED |

Conclusiones:

- Donde DSS da una subindicación de cadena, berigna precisa la causa: `TRY_LATER`, porque falta la revocación. En B-B, DSS no encuentra la cadena (`NO_CERTIFICATE_CHAIN_FOUND`) porque la firma solo lleva el certificado del firmante y DSS tiene solo la raíz; berigna tiene la CA intermedia en su almacén, como con el DNIe real.
- El sello de firma de B-T queda INDETERMINATE por lo mismo: sin la revocación de la TSA. Con los datos suministrados, la B-T pasa (pruebas unitarias).
- El sello de archivo de B-LTA se recalcula sobre la firma tal como está (EN 319 132-1 §5.5.2): PASSED en las nueve B-LTA. Si se añade un certificado a `CertificateValues` después del sellado, la firma sigue TOTAL-PASSED y el sello pasa a TOTAL-FAILED / HASH_FAILURE (PR-TSA-05).

### 3.6 Firmas generadas por DSS (PR-INT-06, 2026-11-02)

DSS 6.2 firma `datos.xml` en las tres variantes y los cuatro niveles (`tests/interop/firmas_dss.py`); berigna verifica sin red y DSS valida:

| Archivo | berigna (`verify_xades`) | DSS 6.2 |
|---|---|---|
| `dss-xades-envuelta-B-B.xml` | INDETERMINATE / TRY_LATER | XAdES-BASELINE-B, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `dss-xades-envuelta-B-T.xml` | INDETERMINATE / TRY_LATER (sello: INDETERMINATE) | XAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `dss-xades-envuelta-B-LT.xml` | TOTAL-PASSED (sello: PASSED) | XAdES-BASELINE-LT, TOTAL_PASSED |
| `dss-xades-envuelta-B-LTA.xml` | TOTAL-PASSED (sellos: PASSED, PASSED) | XAdES-BASELINE-LTA, TOTAL_PASSED |
| `dss-xades-envolvente-B-B.xml` | INDETERMINATE / TRY_LATER | XAdES-BASELINE-B, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `dss-xades-envolvente-B-T.xml` | INDETERMINATE / TRY_LATER (sello: INDETERMINATE) | XAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `dss-xades-envolvente-B-LT.xml` | TOTAL-PASSED (sello: PASSED) | XAdES-BASELINE-LT, TOTAL_PASSED |
| `dss-xades-envolvente-B-LTA.xml` | TOTAL-PASSED (sellos: PASSED, PASSED) | XAdES-BASELINE-LTA, TOTAL_PASSED |
| `dss-xades-separada-B-B.xml` | INDETERMINATE / TRY_LATER | XAdES-BASELINE-B, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `dss-xades-separada-B-T.xml` | INDETERMINATE / TRY_LATER (sello: INDETERMINATE) | XAdES-BASELINE-T, INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| `dss-xades-separada-B-LT.xml` | TOTAL-PASSED (sello: PASSED) | XAdES-BASELINE-LT, TOTAL_PASSED |
| `dss-xades-separada-B-LTA.xml` | TOTAL-PASSED (sellos: PASSED, PASSED) | XAdES-BASELINE-LTA, TOTAL_PASSED |

Conclusiones:

- La indicación principal coincide en las doce: PR-INT-06 se cumple.
- Las firmas de DSS usan lo que las de berigna no: `C14N` exclusiva, `SigningCertificateV2` con SHA-512 y `IssuerSerialV2`, y en la envolvente el documento en base64 dentro de `ds:Object`, con la transformada `base64`. La primera corrida dio FORMAT_FAILURE en las cuatro envolventes porque esa transformada faltaba en la lista permitida; se añadió y se corrió de nuevo.
- berigna da PASSED al sello de archivo que calculó DSS: el cálculo de la cobertura (EN 319 132-1 §5.5.2) coincide con el de un tercero, no solo con el del firmante de berigna.

### 3.7 Firma real de Firma Perú (PR-INT-05, 2026-11-02)

Un documento XML de prueba firmado con Firma Perú y un DNIe real: XAdES-BASELINE-B envuelta, con la referencia `URI=""` y la transformada XPath Filter 2.0 `subtract` de todos los `ds:Signature`, C14N exclusiva y `SigningCertificateV2`, emitida por ECEP-RENIEC CA Class 2 II. La firma y el documento, que llevan el nombre y el DNI del firmante, quedan en la documentación interna.

| Verificación | Resultado |
|---|---|
| berigna en línea (`verificar_firma_peru.py`: almacén propio, TSL de INDECOPI, OCSP y CRL de RENIEC) | TOTAL-PASSED; cubre el documento completo (`SignedScope.DOCUMENT`) |
| berigna sin red | INDETERMINATE / TRY_LATER (sin la revocación, como cualquier B-B) |
| berigna con un precio del documento cambiado | TOTAL-FAILED / HASH_FAILURE |
| DSS 6.2, con ECERNEP PERU CA ROOT 3 como ancla y revocación en línea | XAdES-BASELINE-B, TOTAL_PASSED |

PR-INT-05 se cumple con Firma Perú. ReFirma PDF no firma XML: al abrir el documento responde "El documento seleccionado no tiene la extensión PDF" (2026-11-02), así que en XAdES no hay firma de ReFirma que contrastar; ReFirma se contrasta en PAdES.

### 3.8 Raíz con `xml:lang`: firma con C14N exclusiva (2026-11-02)

Al desarrollar el incremento 5 apareció que la firma envuelta de berigna sobre una raíz con `xml:lang`, `xml:space` o `xml:base` salía inválida, también en DSS 6.2: con la C14N 1.0 inclusiva, las referencias a `SignedProperties` y `KeyInfo` y el propio `SignedInfo` heredan esos atributos, y lxml, signxml y DSS no coinciden en cómo. Primero se probó a heredarlos en la firma, como pide C14N 1.0: DSS aceptó la referencia a `SignedProperties` pero no la de `KeyInfo` ni el valor de la firma. La corrección es firmar con C14N exclusiva `SignedInfo`, `SignedProperties`, `KeyInfo` y el sello de archivo, como DSS y Firma Perú, y dejar la C14N 1.0 en la referencia al objeto de datos, que no hereda nada y así cubre las declaraciones de espacios de nombres usadas solo dentro de valores (ADR-0008, seguimiento del 2026-11-02).

Resultado: la matriz se repitió con `xml:lang` en la raíz de los documentos difíciles, y DSS 6.2 da TOTAL_PASSED en las 18 B-LT y B-LTA, con los sellos de archivo PASSED y sin ningún HASH_FAILURE. Las 36 concuerdan con `verify_xades`, y xmlsec1 verifica en la CI una envuelta sobre una raíz con `xml:lang` y `xml:space`. DSS da también TOTAL_PASSED en B-LTA a un documento con `xsi:type="ns:Tipo"`, y en berigna cambiar después ese prefijo da HASH_FAILURE.

## 4. Pendiente

- La misma matriz con el DNIe real y PIN, y en Firma Perú (incremento 8).
- La firma con `xml:lang` en la raíz, corregida (§3.8), en Firma Perú, junto con el resto de la matriz (incremento 8).
