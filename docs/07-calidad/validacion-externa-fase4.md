# Validación externa de la Fase 4: matriz CAdES y XAdES por niveles

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-006 |
| Versión | 0.3.0 |
| Estado | En curso |
| Fecha | 2026-11-01 |
| Responsable | noggalito |

## 1. Objetivo

Criterio de salida de la Fase 4 (hoja de ruta): la matriz completa de formato × nivel validada por un validador externo. Como en la Fase 2 (BRG-CAL-004), el validador externo es DSS 6.2, la biblioteca de referencia de la Comisión Europea en la que se basa el validador oficial Firma Perú. El documento crece con cada incremento: CAdES (incremento 2), XAdES (incremento 4) y la contrastación con la verificación propia de berigna (incrementos 3 y 5). El cierre llega en el incremento 8, con el DNIe real y PIN.

## 2. Método

1. `tests/interop/matriz_cades.py` firma un mismo archivo de texto en CAdES separada (`.p7s`) y envuelta (`.p7m`), de B-B a B-LTA, con el código de berigna, el DNIe simulado, la PKI de pruebas y una TSA de pruebas.
2. `tests/interop/matriz_xades.py` firma un mismo documento XML (`datos.xml`) en XAdES envuelta, envolvente y separada (`.xsig`, que referencia a `datos.xml`), de B-B a B-LTA, con los mismos medios.
3. `tests/interop/matriz_dss.sh` valida todos los archivos con DSS 6.2 (arnés de SPK-03), con la raíz de pruebas como única ancla. Una `.p7s` se valida contra `datos.txt` y una `.xsig` contra `datos.xml`. Las URL de revocación de la PKI de pruebas no responden, así que DSS trabaja solo con lo que la firma trae.
4. Verificación propia de berigna (incremento 3): la misma matriz CAdES se relee con `berigna.core.validation.cades.verify_cades` (RF-051), sin red, y sus indicaciones y subindicaciones quedan junto a las de DSS. Lo propio con XAdES llega con el incremento 5.

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

## 4. Pendiente

- La misma matriz con el DNIe real y PIN, y en Firma Perú (incremento 8).
