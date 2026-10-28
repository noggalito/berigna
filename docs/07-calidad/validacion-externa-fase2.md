# Validación externa de la Fase 2: matriz PAdES por niveles

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-004 |
| Versión | 0.1.0 |
| Estado | Vigente |
| Fecha | 2026-10-28 |
| Responsable | `{{TITULAR}}` |

## 1. Objetivo

Criterio de salida de la Fase 2 (hoja de ruta): una matriz PAdES × niveles validada por un validador externo, y la verificación propia de berigna (RF-050, RF-053, RF-055) contrastada con él. El validador externo es DSS 6.2, la biblioteca de referencia de la Comisión Europea en la que se basa el validador oficial Firma Perú (SPK-03).

## 2. Método

1. `tests/interop/matriz_pades.py` firma un PDF de prueba por nivel (B-B, B-T, B-LT y B-LTA) con el código de berigna, el DNIe simulado, la PKI de pruebas y una TSA de pruebas. Después verifica cada archivo con berigna, sin red y solo con lo que el documento trae.
2. `tests/interop/matriz_dss.sh` valida los mismos archivos con DSS 6.2 (arnés de SPK-03), con la raíz de pruebas como única ancla. Las URL de revocación de la PKI de pruebas no responden, así que DSS también trabaja solo con lo que el documento trae.
3. Además se contrastan documentos reales: un PDF B-B firmado con el DNIe real del titular, en línea, y tres documentos públicos del Estado con firmas de RENIEC, con ROOT 3 y ROOT 5 como anclas en ambos validadores.

Para repetirlo: `.venv/bin/python tests/interop/matriz_pades.py DIR` y `tests/interop/matriz_dss.sh DIR [dssval]`.

## 3. Resultados (2026-10-28)

### 3.1 Matriz por niveles (PKI y TSA de pruebas)

| Nivel pedido | Nivel alcanzado (berigna) | Formato según DSS | berigna | DSS 6.2 |
|---|---|---|---|---|
| B-B | B-B | PAdES-BASELINE-B | INDETERMINATE / TRY_LATER | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| B-T | B-T | PAdES-BASELINE-T | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE |
| B-LT | B-LT | PAdES-BASELINE-LT | TOTAL-PASSED | TOTAL_PASSED |
| B-LTA | B-LTA | PAdES-BASELINE-LTA | TOTAL-PASSED (sello de firma y sello de documento válidos) | TOTAL_PASSED |

- DSS reconoce cada archivo con el nivel que berigna declara haber producido.
- La indicación principal coincide en los cuatro niveles. B-B y B-T no llevan datos de revocación, así que ningún validador puede dar más que INDETERMINATE sin consultar la red; es el resultado esperado.
- En B-B, berigna precisa la causa (`TRY_LATER`: faltan datos de revocación) donde DSS da la subindicación genérica; en este caso la URL de revocación no responde.

### 3.2 Documentos reales (en línea, anclas ROOT 3 y ROOT 5)

| Documento | berigna | DSS 6.2 |
|---|---|---|
| PDF propio firmado con el DNIe real (B-B) | TOTAL-PASSED | PAdES-BASELINE-B, TOTAL_PASSED |
| Documento público 1 (firmante revocado después de firmar, sin sello) | INDETERMINATE / REVOKED_NO_POE | PAdES-BASELINE-B, INDETERMINATE / REVOKED_NO_POE |
| Documento público 2 (firmas heredadas de Adobe, CA intermedia vencida) | INDETERMINATE / OUT_OF_BOUNDS_NO_POE | PKCS7-B, INDETERMINATE / TRY_LATER |
| Documento público 4 (ídem) | INDETERMINATE / OUT_OF_BOUNDS_NO_POE | PKCS7-B, INDETERMINATE / TRY_LATER |

En los documentos públicos 2 y 4, DSS comprueba primero la revocación y berigna informa primero la causa de la cadena. La indicación principal coincide. El PDF propio fue además validado en Firma Perú (`PAdES_BASELINE_B`, raíz en TSL; Fase 0).

## 4. Conclusión

La indicación principal de berigna coincide con la de DSS 6.2 en los 8 casos, y DSS confirma los cuatro niveles producidos. Criterio de salida de la Fase 2 cumplido para PAdES.

Pendiente, sin bloquear el cierre de la fase: B-T a B-LTA con el DNIe real y una TSA peruana acreditada (DP-02) validados en Firma Perú, que se añadirán a este documento cuando haya TSA contratada (PR-INT-01).
