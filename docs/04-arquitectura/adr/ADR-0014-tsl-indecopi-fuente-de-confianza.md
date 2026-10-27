# ADR-0014: La TSL de INDECOPI como fuente del almacén de confianza

- Estado: Propuesto (pendiente de la URL oficial de la TSL, consulta Q8 / CE-01)
- Fecha: 2026-10-27
- Complementa: ADR-0009

## Contexto

ADR-0009 establece un almacén de confianza propio con las raíces de la IOFE, pero no dice de dónde se obtienen ni cómo se mantienen al día. La guía de acreditación de software v4.0 de INDECOPI (§3.3 y §4.1) describe una Lista de Servicios de Confianza (TSL, ETSI TS 102 231) firmada por INDECOPI. Su verificación no es obligatoria para acreditar (ACR-24), pero sí recomendable. El validador oficial Firma Perú ya la usa: su informe muestra "Certificado raíz del firmante en TSL: Sí" (SPK-03 §7). En la práctica hay al menos dos jerarquías del Estado (ROOT 3 y ROOT 5; SPK-03 §5).

## Propuesta

1. La fuente de las anclas de confianza de ADR-0009 es la TSL de INDECOPI.
2. Durante la construcción del paquete (no en tiempo de ejecución) se descarga la TSL, se verifica su firma contra el certificado de INDECOPI fijado en el código y su vigencia (`NextUpdate`), y se generan `trust/` y `trust/manifest.json` (BRG-ARQ-003 §3).
3. En tiempo de ejecución, berigna puede comprobar opcionalmente si existe una TSL más reciente y avisar al usuario, pero no cambia el almacén sin una actualización del paquete (RF-061).
4. Hasta conocer la URL oficial, el almacén se construye a mano con las raíces e intermedias verificadas (SPK-02 §3.1, SPK-03 §5), con sus huellas documentadas.

## Consecuencias

- ACR-24 pasa a estar cubierto por este ADR cuando se acepte.
- El proceso de publicación de versiones incluye regenerar el almacén desde la TSL.
- Hace falta un analizador de TSL (XML firmado). Se puede reutilizar la verificación XAdES/XMLDSig de `core.formats.xades`.

## Criterio de aceptación

URL oficial de la TSL confirmada por INDECOPI y un prototipo que la descargue, verifique y extraiga las raíces de ROOT 3 y ROOT 5.
