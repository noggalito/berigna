# Validación externa de la Fase 4: matriz CAdES y XAdES por niveles

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-006 |
| Versión | 0.2.0 |
| Estado | En curso |
| Fecha | 2026-10-30 |
| Responsable | noggalito |

## 1. Objetivo

Criterio de salida de la Fase 4 (hoja de ruta): la matriz completa de formato × nivel validada por un validador externo. Como en la Fase 2 (BRG-CAL-004), el validador externo es DSS 6.2, la biblioteca de referencia de la Comisión Europea en la que se basa el validador oficial Firma Perú. El documento crece con cada incremento: CAdES (incremento 2), XAdES (incremento 4) y la contrastación con la verificación propia de berigna (incrementos 3 y 5). El cierre llega en el incremento 8, con el DNIe real y PIN.

## 2. Método

1. `tests/interop/matriz_cades.py` firma un mismo archivo de texto en CAdES separada (`.p7s`) y envuelta (`.p7m`), de B-B a B-LTA, con el código de berigna, el DNIe simulado, la PKI de pruebas y una TSA de pruebas.
2. `tests/interop/matriz_dss.sh` valida los archivos con DSS 6.2 (arnés de SPK-03), con la raíz de pruebas como única ancla. Una `.p7s` se valida contra el archivo firmado. Las URL de revocación de la PKI de pruebas no responden, así que DSS trabaja solo con lo que la firma trae.
3. Verificación propia de berigna (incremento 3): la misma matriz se relee con `berigna.core.validation.cades.verify_cades` (RF-051), sin red, y sus indicaciones y subindicaciones quedan junto a las de DSS.

Para repetirlo: `.venv/bin/python tests/interop/matriz_cades.py DIR` y `tests/interop/matriz_dss.sh DIR [dssval]`. El arnés se prepara con `spikes/preparar-entorno.sh`; si el sistema solo tiene el entorno de ejecución de Java 21, el JDK 8 compila `Validate.java` con las bibliotecas de DSS 6.2.

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

### 3.3 XAdES

Pendiente (incremento 4).

## 4. Pendiente

- La misma matriz con el DNIe real y PIN, y en Firma Perú (incremento 8).
