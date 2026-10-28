# ADR-0014: La TSL de INDECOPI como fuente del almacén de confianza

- Estado: Aceptado (2026-10-28)
- Fecha: 2026-10-27 (propuesta); 2026-10-28 (aceptación)
- Complementa: ADR-0009

## Contexto

ADR-0009 establece un almacén de confianza propio con las raíces de la IOFE, pero no dice de dónde se obtienen ni cómo se mantienen al día. La guía de acreditación de software v4.0 de INDECOPI (§3.3 y §4.1) describe una Lista de Servicios de Confianza (TSL, ETSI TS 102 231 / TS 119 612) firmada por INDECOPI. Su verificación no es obligatoria para acreditar (ACR-24), pero sí recomendable. El validador oficial Firma Perú ya la usa: su informe muestra "Certificado raíz del firmante en TSL: Sí" (SPK-03 §7).

La TSL está publicada en el dominio de INDECOPI (`https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`; consultada el 2026-10-28: versión 3, secuencia 25, emitida el 2026-08-10, vigente hasta el 2027-02-10). La firma un certificado "TSL Suscriptor" emitido por INDECOPI AAC RAIZ, cuyo certificado se obtiene de la dirección indicada en el propio firmante (`https://recursos.indecopi.gob.pe/iofe/crt/ca_root_indecopi.crt`). La lista contiene ROOT 3 y ROOT 5 y además ECERNEP PERU CA ROOT 6, que el almacén base no tenía, y las TSA acreditadas.

## Decisión

1. La raíz de la TSL (INDECOPI AAC RAIZ) se fija en el paquete: su certificado va en `core/trust/tsl/` y su huella SHA-256 (`6cf85e75…5f9375`) en el código (`core.trust.tsl`). Un archivo que no coincide se rechaza.
2. Antes de usar la TSL, berigna comprueba: tamaño y XML sin entidades ni red; que el firmante lo emite la raíz fijada, ambos vigentes, con uso de firma y no revocado (CRL de INDECOPI); la firma XML (signxml) con ese firmante y una referencia SHA-256 o superior que cubre la lista entera; que la lista está vigente (`NextUpdate`) y que no es más antigua que la última aceptada. Solo se lee el elemento firmado, nunca el documento descargado.
3. Las CA de los servicios en estado aceptado ("undersupervision" o los estados ETSI equivalentes) se añaden en tiempo de ejecución al almacén base de ADR-0009, con origen "TSL": las autoemitidas como raíces y las demás como intermedias.
4. El almacén base del paquete sigue siendo el respaldo: si la TSL no se puede descargar, no verifica o está vencida, berigna sigue con el almacén base y lo indica (ERR-203, ERR-204).
5. La descarga periódica, la caché de la última TSL aceptada y la persistencia de su número de secuencia corresponden a la capa de configuración (Fase 3).

## Notas de implementación

- La referencia de la firma al certificado firmante usa SHA-1. Se tolera porque berigna verifica ese certificado por su cuenta contra la raíz fijada; la referencia que cubre la lista exige SHA-256 o superior.
- Algunas raíces acreditadas (GSE, Certicámara) tienen extensiones que `cryptography` no acepta; los certificados de la TSL se clasifican con asn1crypto, igual que el validador de firmas.
- La raíz de INDECOPI declara `C=PERU` (el código de país debe tener dos letras); `cryptography` lo avisa sin rechazarlo.

## Alternativas consideradas

- Generar el almacén desde la TSL solo al construir el paquete: se descartó como única vía porque una nueva CA acreditada (como ROOT 6) no se reconocería hasta la siguiente versión. El almacén base se sigue revisando en cada versión.
- Confiar en la TSL sin raíz fijada (solo por HTTPS): se descartó; el canal no sustituye la firma.

## Consecuencias

- ACR-24 queda cubierto.
- RF-061 se amplía: además de actualizarse con el paquete, el almacén incorpora las CA de la TSL verificada.
- Pendiente: que INDECOPI confirme la URL y la huella de la raíz (CE-01, pregunta 8).
