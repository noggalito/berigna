# SPK-07: Lectura sin contacto (NFC) del DNIe y firma desde el teléfono

| Campo | Valor |
|---|---|
| Documento | BRG-INV-007 |
| Versión | 0.1.0 |
| Estado | Pendiente |
| Fecha | 2026-10-29 |
| Responsable | noggalito |

## 1. Contexto

La v1.0 solo admite lectores USB de contacto (ADR-0003). El titular decidió (2026-10-29) estudiar para la versión 1.1 la lectura sin contacto del DNIe y su uso desde el teléfono. Comprar un lector es la principal barrera para quien quiere firmar con su DNIe, y muchos teléfonos Android y los iPhone tienen NFC.

Las fuentes públicas no coinciden sobre qué versión del DNIe admite NFC: unas lo atribuyen al DNIe 2.0 y otras solo al DNIe 3.0. ADR-0012 ya prevé que el driver `dnie_v2` reconozca por su ATR el DNIe leído sin contacto. Este *spike* complementa la pregunta 6 de SPK-06.

## 2. Opciones que se evalúan

| Opción | Descripción | Qué se reutiliza |
|---|---|---|
| A. Lector NFC en el escritorio | Un lector de escritorio sin contacto o dual que se presenta como lector PC/SC | Todo: berigna no cambia, salvo los ATR y, si hiciera falta, PACE |
| B. berigna en Android | Aplicación que firma y verifica en el propio teléfono, leyendo el DNIe por NFC (`IsoDep`) | El núcleo, si se ejecuta en Android (por ejemplo, con Chaquopy) con un transporte `IsoDep` en lugar de PC/SC (`core.token.transport`); si no, el protocolo, el simulador y los vectores de prueba como especificación |
| C. El teléfono como puente | El teléfono solo hace de lector: recibe por un canal emparejado los APDU de berigna en el escritorio, los pasa al DNIe por NFC y devuelve las respuestas | Todo el escritorio; en el teléfono, una aplicación pequeña sin lógica de firma |

## 3. Preguntas

1. ¿Qué versiones del DNIe (1.0, 2.0, 3.0) tienen interfaz sin contacto? ¿Qué ATR o ATS presentan por NFC?
2. ¿El acceso sin contacto exige PACE con el CAN impreso en la tarjeta, u otro protocolo? ¿Responde el *applet* PKI (`E828BD080FD250 "Generic"`) sin él?
3. Una vez abierto el canal, ¿se aplica la misma secuencia que por contacto (archivos `001B` a `001D`, VERIFY `0x81`, MSE:SET y PSO:CDS)? ¿Hay mensajería segura (*secure messaging*) obligatoria?
4. ¿Hacen falta APDU de longitud extendida (la firma RSA 2048 devuelve 256 bytes)? ¿Qué teléfonos los admiten (`IsoDep.isExtendedLengthApduSupported()` en Android; Core NFC en iOS)?
5. ¿Cuánto tarda una firma por NFC y con qué frecuencia se corta la comunicación si se mueve la tarjeta? ¿Qué pasa si se corta a mitad de una firma, después del VERIFY?
6. Opción A: ¿qué lectores sin contacto o duales disponibles en el Perú funcionan con `pcscd` y `libccid` de Debian 13?
7. Opción B: ¿se pueden ejecutar en Android las dependencias del núcleo (cryptography, lxml, pyHanko, asn1crypto)? Si no, ¿qué bibliotecas libres harían lo mismo (por ejemplo, PDFBox y BouncyCastle; iText queda descartado por su licencia AGPL)?
8. Opción C: ¿qué canal entre teléfono y escritorio (USB, Bluetooth, red local) es viable y cómo se empareja de forma segura?
9. iOS: ¿Core NFC permite seleccionar el AID del *applet* PKI (`com.apple.developer.nfc.readersession.iso7816.select-identifiers`) y enviar la secuencia completa?

## 4. Seguridad

Cada opción lleva su propia ampliación del modelo de amenazas (BRG-SEG-001) antes de pasar a código:

- **PIN.** En la opción C, si el PIN se escribe en el escritorio, el APDU VERIFY lo lleva en claro a través del teléfono, salvo que haya mensajería segura entre la tarjeta y berigna en el escritorio. Hay dos salidas: que el canal con la tarjeta termine en el escritorio (PACE desde berigna, de modo que el teléfono solo vea datos cifrados), o que el PIN se escriba en el teléfono y nunca llegue al escritorio. Se decide según la respuesta a la pregunta 3.
- **Relé.** La opción C es, por diseño, un relé de APDU. El emparejamiento debe autenticar ambos extremos (por ejemplo, con un código QR de un solo uso), cifrar el canal y aceptar solo la lista blanca de comandos del driver (ADR-0012), en los dos extremos.
- **Consentimiento.** En el teléfono hay que mostrar qué se va a firmar (al menos el nombre del archivo y su *hash*) antes de pedir el PIN, como en RF-018.
- **Plataforma.** En Android hay que considerar el *malware* con permisos de accesibilidad, que puede leer lo que se escribe; en iOS, las condiciones de la App Store (ADR-0021).

## 5. Método

1. Opción A primero, porque es la más barata y responde las preguntas 1 a 3 sin escribir una aplicación: un lector sin contacto o dual por PC/SC, con `spikes/spk01/` (`read_certs.py`, `reader_profile.py`) y `opensc-tool`, solo lectura y **sin PIN** (protocolo de PIN, regla PIN-07).
2. Con el canal confirmado, un prototipo mínimo en Android que lea el certificado de firma por `IsoDep`, también sin PIN.
3. La firma con PIN, si hace falta, la ejecuta su titular con su propio DNIe, siguiendo el protocolo.

No se publica ningún dato personal de las tarjetas usadas.

## 6. Criterio de cierre

- Para cada versión del DNIe: si admite NFC, con qué protocolo de acceso y con qué secuencia de firma.
- Una recomendación entre las opciones A, B y C para la versión 1.1, con su costo estimado y el análisis de amenazas de §4.
- Las implicaciones para la acreditación, pendientes de consultar a INDECOPI: si el expediente cubre cada plataforma o si cada una se evalúa por separado.
