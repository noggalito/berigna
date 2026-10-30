# ADR-0022: Toda CA acreditada en la TSL como ancla de confianza

- Estado: Aceptado
- Fecha: 2026-10-30
- Origen: Corrección del fallo de construcción de ruta en sellos de tiempo de prestadores acreditados (2026-10-30); complementa [ADR-0009](ADR-0009-almacen-confianza-propio.md) y [ADR-0014](ADR-0014-tsl-indecopi-fuente-de-confianza.md)

## Contexto

ADR-0014 integró la Lista de Servicios de Confianza (TSL) de INDECOPI como fuente dinámica del almacén de confianza, clasificando las CA autoemitidas (*self-issued*) como raíces y las subordinadas como intermedias en el `TrustStore`.

El 2026-10-30, la verificación de un documento real con sellos de tiempo de la Entidad de Certificación de Sellado de Tiempo (TSA) de Soft & Net Solutions falló con `PathBuildingError`:
- El certificado de la TSA de Soft & Net está emitido por `Camerfirma TSA II - 2014`.
- `Camerfirma TSA II - 2014` está listada en la TSL en estado aceptado, pero no es autofirmada: su emisor es `Chambers of Commerce Root - 2008`.
- Esa raíz superior (`Chambers of Commerce Root - 2008`) no figura en la TSL de INDECOPI ni en el almacén base de la IOFE de berigna.
- Al agregarse como "intermedia", el validador estricto (`pyhanko_certvalidator`) exigió construir la cadena hasta una raíz autofirmada de confianza, fallando al no encontrar el emisor superior en el almacén.

De acuerdo con el estándar ETSI TS 119 612 y el marco normativo de la IOFE, cuando la autoridad de supervisión (INDECOPI) acredita un servicio de confianza y publica su certificado en la TSL con estado aceptado (*undersupervision* o equivalentes), dicho certificado tiene presunción legal de confianza y debe actuar como ancla de confianza (*trust anchor*) por derecho propio, sin supeditarse a jerarquías foráneas no acreditadas.

Asimismo, durante la construcción de rutas no encontradas, `pyhanko_certvalidator` emitía trazas completas (*tracebacks*) directamente en la terminal estándar, saturando la salida de usuario cuando el resultado de la verificación ya dictamina formalmente la causa.

## Decisión

1. **Toda CA acreditada es ancla:** En `core.trust.tsl`, todo certificado de CA (`_is_ca`) perteneciente a un servicio en estado aceptado de la TSL se incorpora al almacén en tiempo de ejecución con rol de ancla de confianza (`role="root"`), sea o no autoemitido. La construcción de la cadena de confianza finaliza válidamente en él.
2. **Representación fiel en la interfaz:** En la vista del almacén de confianza de las Preferencias (`ui.presentation.trust_store_view`), los certificados se describen según su naturaleza intrínseca (`certificate.subject == certificate.issuer` es «Raíz», los demás «Intermedio»), manteniendo la claridad visual para el usuario mientras operan técnicamente como anclas.
3. **Canalización y enmascaramiento de trazas de librerías:** Los registradores de `pyhanko` y `pyhanko_certvalidator` se redirigen exclusivamente al archivo de registro técnico rotativo (`berigna.log`) a través de `MaskingFormatter` (con enmascaramiento estricto de números y DNI, RNF-SEG-07), evitando cualquier emisión ruidosa de trazas hacia la terminal estándar (`stderr`).
4. **Supresión del aviso de longitud de atributos en la raíz:** Se lee la raíz de INDECOPI suprimiendo el aviso no estándar de `cryptography` respecto al código de país `C=PERU`.

## Alternativas consideradas

- **Incluir manualmente raíces extranjeras superiores en el almacén base:** Inviable e indebido: `Chambers of Commerce Root - 2008` no está acreditada ante INDECOPI; incorporar raíces externas diluye la frontera de confianza de la IOFE (ADR-0009).
- **Tratar intermedias como anclas solo para TSA:** Complejidad innecesaria. El acto de acreditación en la TSL ampara a cualquier servicio aceptado en la lista oficial.

## Consecuencias

- Se anclan correctamente certificados y sellos emitidos bajo intermedias acreditadas en la TSL (como Soft & Net / Camerfirma).
- El informe técnico y la terminal permanecen limpios y legibles, preservando el enmascaramiento de datos personales en el registro rotativo.
- Se actualizan las pruebas unitarias y de interfaz para verificar tanto el anclaje sin raíz superior como la presentación en Preferencias.
