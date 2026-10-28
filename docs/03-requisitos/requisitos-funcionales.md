# Requisitos funcionales

| Campo | Valor |
|---|---|
| Documento | BRG-REQ-001 |
| Versión | 0.3.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

Prioridades según MoSCoW (ver convenciones). Cada requisito tiene criterios de aceptación verificables. La columna CU indica los casos de uso relacionados.

## 1. Dispositivo y certificados

### RF-001: Detección de lectores
- Prioridad: Debe. CU: CU-01, CU-07.
- Descripción: la aplicación detecta los lectores PC/SC conectados y reacciona a su conexión y desconexión en caliente, sin reiniciarse.
- Aceptación:
  1. Al conectar un lector, la interfaz lo refleja en menos de 2 s.
  2. Si no hay lector, se muestra el estado "Conecta un lector de tarjetas" con un enlace al diagnóstico.
  3. Si el servicio `pcscd` no está disponible, se muestra un mensaje específico con su solución.
  4. No se guarda el lector por su nombre PC/SC, que cambia con cada modelo (SPK-01 §8.5). Se usa el lector que tenga una tarjeta con un ATR soportado y, si hay varios, se pregunta al usuario.

### RF-002: Detección del DNIe
- Prioridad: Debe. CU: CU-01.
- Descripción: se detecta la inserción y el retiro de la tarjeta, y se identifica si es un DNIe compatible.
- Aceptación:
  1. Al insertar un DNIe, el estado cambia a "DNIe detectado" y se leen sus certificados.
  2. Una tarjeta no reconocida produce el mensaje "Tarjeta no compatible", acompañado del ATR para soporte técnico.
  3. Si se retira la tarjeta durante una operación, la operación se aborta de forma segura sin dejar archivos de salida corruptos.
  4. El DNIe v2 se reconoce por su ATR (`3B DC 18 FF 81 91 FE 1F C3 80 73 C8 21 13 66 05 03 63 51 00 02 50`) y usa el driver `dnie_v2` (ADR-0012). El resto de tarjetas se intenta mediante PKCS#11.

### RF-003: Lectura y presentación de certificados
- Prioridad: Debe. CU: CU-01, CU-07.
- Descripción: se leen los certificados del *token* sin pedir el PIN, si el chip lo permite, y se muestran el nombre del titular, el número de DNI, el emisor, la vigencia, el uso de clave y la huella SHA-256.
- Aceptación: los datos mostrados coinciden con los de `pkcs11-tool --read-object` (con el *backend* PKCS#11) o con la lectura de referencia de SPK-01 (con el DNIe v2). Con el DNIe v2, la lectura se detiene al alcanzar la longitud indicada en la cabecera DER, y los certificados se guardan en caché mientras la tarjeta siga insertada. Al insertar la tarjeta solo se lee el certificado de firma (medido: unos 0,67 s parando en la longitud DER, SPK-01 §8.5; objetivo: menos de 1 s). Los certificados de autenticación y de cifrado se leen bajo demanda, solo si se muestran.

### RF-004: Selección del certificado de firma
- Prioridad: Debe. CU: CU-01.
- Descripción: se selecciona automáticamente el certificado con uso de clave de no repudio (`contentCommitment`). El certificado de autenticación no se ofrece para firmar (ver DP-09).
- Aceptación: con un *token* que tenga ambos certificados, la firma generada siempre contiene el certificado de no repudio.

### RF-005: Autenticación con PIN
- Prioridad: Debe. CU: CU-01, CU-04.
- Descripción: se solicita el PIN en un diálogo propio, justo antes de la operación y después de que el usuario haya revisado lo que va a firmar. El soporte de PIN pad queda aplazado a la versión 1.1 (decisión del 2026-10-27): hace falta un lector de clase 2 para desarrollarlo y probarlo. Si el lector tiene PIN pad, se pide al usuario que lo teclee en el lector. La detección depende del *backend*: `CKF_PROTECTED_AUTHENTICATION_PATH` (PKCS#11) o `FEATURE_VERIFY_PIN_DIRECT` de PC/SC parte 10 (driver del DNIe v2, ADR-0012).
- Aceptación:
  1. El campo del PIN oculta los caracteres y no se puede copiar de él.
  2. Si el *token* informa de que quedan pocos intentos, se muestra una advertencia antes de enviar el PIN. Con PKCS#11: `CKF_USER_PIN_COUNT_LOW` o `CKF_USER_PIN_FINAL_TRY`. Con el DNIe v2 el contador se conoce por la respuesta `63Cx` de un VERIFY fallido; no se consulta por adelantado mientras no se confirme que la consulta sin datos no consume intentos (SPK-01 §9, punto 1).
  3. Si el PIN es incorrecto, se informa sin revelar detalles internos y se indican los intentos restantes si se conocen (`63Cx`). Si está bloqueado (`CKR_PIN_LOCKED` en PKCS#11; `6983` en el DNIe v2), se explica cómo desbloquearlo ante RENIEC.
  4. El PIN no persiste en memoria más allá de la sesión de firma (ver 05-seguridad).

### RF-006: Validación previa del certificado del firmante
- Prioridad: Debe. CU: CU-01.
- Descripción: antes de pedir el PIN se comprueban la vigencia, la cadena hasta una raíz de confianza de la IOFE y el estado de revocación mediante OCSP. La CRL no se usa en el flujo de firma: la de la CA del DNIe pesa unos 109 MB (RF-063, SPK-02). Si INDECOPI exigiera la CRL (consulta Q1 de SPK-04), este requisito se revisará.
- Aceptación:
  1. Con un certificado caducado o revocado, la firma se bloquea con un mensaje claro.
  2. Si no se puede comprobar la revocación (sin conexión), se advierte al usuario y solo se le deja continuar con el nivel B-B, dejando constancia en el historial.

### RF-007: Asistente de diagnóstico
- Prioridad: Debe. CU: CU-07.
- Descripción: un asistente comprueba en orden el servicio `pcscd`, el lector, la tarjeta, el *backend* activo (driver APDU elegido por el ATR o módulo PKCS#11), los certificados y la conectividad con la TSA y con OCSP. Muestra un resultado por paso y una acción sugerida.
- Aceptación: genera un informe copiable sin datos sensibles (sin PIN y con el número de DNI enmascarado).

## 2. Firma PAdES

### RF-010: Firma PAdES con nivel seleccionable
- Prioridad: Debe. CU: CU-01, CU-02.
- Descripción: se firma un PDF en el nivel B-B, B-T, B-LT o B-LTA que elija el usuario. El nivel por defecto es configurable (DP-04). Al elegir un nivel inferior a B-LT se muestra una nota sobre su validez a largo plazo.
- Aceptación: para cada nivel, un validador conforme a ETSI identifica el nivel declarado y da un resultado TOTAL-PASSED.

### RF-011: Firma invisible
- Prioridad: Debe. Descripción: la firma no tiene apariencia gráfica.

### RF-012: Firma visible configurable
- Prioridad: Debe. CU: CU-02.
- Descripción: el usuario coloca un recuadro de firma sobre la previsualización (arrastrando para definir posición y tamaño) en la página que elija (primera, última o una concreta). La apariencia combina:
  - texto con una plantilla con variables (`{nombre}`, `{dni}`, `{fecha}`, `{motivo}`, `{ubicacion}`);
  - una imagen opcional (PNG o JPEG, por ejemplo una rúbrica o un logotipo).
- Aceptación: la apariencia se ve igual en Evince/Papers, Okular y Adobe Acrobat Reader.

### RF-013: Metadatos de la firma
- Prioridad: Debe. Descripción: campos opcionales de motivo, ubicación y contacto. Se recuerdan los últimos valores usados.

### RF-014: Firmas sucesivas
- Prioridad: Debe. CU: CU-03.
- Descripción: firmar un PDF que ya está firmado añade la firma mediante una actualización incremental, sin invalidar las firmas existentes.
- Aceptación: tras la segunda firma, ambas siguen siendo válidas.

### RF-015: Firma de certificación (DocMDP)
- Prioridad: Debería.
- Descripción: opción "Certificar documento" con un nivel de permisos (sin cambios; solo formularios; formularios y anotaciones). Solo se permite si el documento no tiene firmas previas.

### RF-016: PDF protegidos
- Prioridad: Debería.
- Descripción: si el PDF está cifrado, se pide su contraseña. Si los permisos del PDF prohíben modificarlo, se informa y no se firma.

### RF-017: Preservación de PDF/A
- Prioridad: Debería.
- Descripción: si el PDF declara conformidad PDF/A, la firma no debe romperla. Si una opción elegida la rompería (por ejemplo, una imagen con transparencia en PDF/A-1), se advierte al usuario.

### RF-018: Previsualización antes de firmar (WYSIWYS)
- Prioridad: Debe. CU: CU-01.
- Descripción: el documento se muestra antes de firmar. El *hash* se calcula sobre los mismos bytes que se cargaron para la previsualización; si el archivo cambia en disco entre la previsualización y la firma, se aborta.
- Aceptación: una prueba que modifica el archivo después de cargarlo provoca la cancelación con su mensaje.

### RF-019: Ampliación del nivel de una firma existente
- Prioridad: Podría.
- Descripción: subir una firma existente a B-LT o B-LTA (añadir datos de validación y un sello de archivo) sin volver a firmar. También permite renovar el sello de archivo de documentos B-LTA.

## 3. Firma CAdES

### RF-020: CAdES separada (`.p7s`)
- Prioridad: Debe. CU: CU-05.
- Descripción: se firma cualquier archivo y se genera `<archivo>.p7s` junto al original, que no se modifica.

### RF-021: CAdES envuelta (`.p7m`)
- Prioridad: Debe. Descripción: se genera `<archivo>.p7m`, que contiene el archivo original.

### RF-022: Niveles CAdES
- Prioridad: Debe. Descripción: B-B, B-T, B-LT y B-LTA, seleccionables, con las mismas reglas que RF-010.

### RF-023: Cofirma CAdES
- Prioridad: Podría. Descripción: añadir una firma paralela (otro firmante) a un `.p7s` o `.p7m` existente.

## 4. Firma XAdES

### RF-030: XAdES envuelta (*enveloped*)
- Prioridad: Debe. Descripción: la firma se inserta dentro del XML firmado.
### RF-031: XAdES envolvente (*enveloping*)
- Prioridad: Debería. Descripción: el contenido va dentro del elemento `ds:Object` de la firma.
### RF-032: XAdES separada (*detached*)
- Prioridad: Debería. Descripción: la firma referencia un archivo externo.
### RF-033: Niveles XAdES
- Prioridad: Debe. Descripción: B-B, B-T, B-LT y B-LTA, seleccionables (viabilidad confirmada en SPK-03; ADR-0008).

## 5. Firma por lotes

### RF-040: Lote con un único PIN
- Prioridad: Debe. CU: CU-04.
- Descripción: se firman N archivos con una sola sesión de *token* autenticada (PKCS#11 o driver APDU). El PIN se pide una vez. Antes de pedirlo se muestra la lista completa de archivos y el usuario la confirma.
- Aceptación: un lote de 50 PDF pide el PIN exactamente una vez. Si el chip exige el PIN en cada operación (`CKA_ALWAYS_AUTHENTICATE` en PKCS#11), se informa y se usa el PIN pad o se solicita el PIN en cada firma. En el DNIe v2 está comprobado que un solo VERIFY basta para todo el lote (SPK-01 §8.6). Al terminar, cancelar o fallar, la tarjeta se reinicia o se apaga para cerrar la sesión.

### RF-041: Composición del lote
- Prioridad: Debe. Descripción: se añaden archivos y carpetas (con opción recursiva). Se aplica PAdES a los PDF, XAdES a los XML y CAdES al resto, salvo que el usuario elija otra cosa.

### RF-042: Informe del lote
- Prioridad: Debe. Descripción: resultado por archivo (correcto, error y motivo, omitido), exportable a CSV.

### RF-043: Tolerancia a fallos y cancelación
- Prioridad: Debe. Descripción: un error en un archivo no detiene el lote. El usuario puede cancelar entre archivos. Al terminar o cancelar se cierra la sesión del *token*.

### RF-045: Salida de los archivos firmados
- Prioridad: Debe.
- Descripción: por defecto, el archivo firmado se guarda junto al original con el sufijo configurable `-firmado`. Nunca se sobrescribe el original sin una confirmación explícita. Si el destino existe, se añade un número (`-firmado-2`).
- Aceptación: la escritura es atómica (archivo temporal y renombrado); no quedan archivos parciales ante un fallo.

## 6. Verificación

### RF-050: Verificación de PAdES
- Prioridad: Debe. CU: CU-06.
- Descripción: se validan todas las firmas y sellos de tiempo de un PDF: integridad, cadena, revocación (en línea o con los datos embebidos) y sello de tiempo. Se incluyen las firmas heredadas `adbe.pkcs7.detached` con el atributo de Adobe `revocationInfoArchival` (1.2.840.113583.1.1.8), que usan documentos públicos del Estado (SPK-04 §3.6).

### RF-051: Verificación de CAdES
- Prioridad: Debe. Descripción: para `.p7s`, se pide o se detecta automáticamente el archivo original (mismo nombre sin extensión). Para `.p7m`, se permite extraer el contenido.

### RF-052: Verificación de XAdES
- Prioridad: Debe.

### RF-053: Resultado normalizado y comprensible
- Prioridad: Debe.
- Descripción: cada firma recibe una indicación según ETSI EN 319 102-1 (TOTAL-PASSED, TOTAL-FAILED o INDETERMINATE, con su subindicación) y una explicación en lenguaje llano en el idioma de la interfaz, por ejemplo:
  - es_PE: "La firma es válida. El documento no ha sido modificado desde que Juan Pérez lo firmó el 27/10/2026 a las 10:15 (hora certificada por la TSA)."
  - quechua: texto equivalente redactado por los traductores (ADR-0015). El ejemplo en en_US se conserva para la versión 1.1: "The signature is valid. The document has not been modified since Juan Pérez signed it on 10/27/2026 at 10:15 AM (time certified by the TSA)."
- Aceptación: todas las combinaciones de indicación y subindicación tienen su explicación en es_PE y en quechua. El informe muestra además el estado de cada sello de tiempo (de firma, de archivo y de documento) por separado: un sello de archivo inválido se señala aunque la firma sea válida en la fecha actual (SPK-03 §5).

### RF-054: Informe exportable
- Prioridad: Debe. Descripción: se exporta un informe en PDF (legible) y en JSON (para máquinas). Debería poder exportarse también en XML según ETSI TS 119 102-2. El informe PDF se genera en es_PE o en quechua, a elección del usuario (por defecto, el idioma de la interfaz). El JSON lleva los códigos normalizados y las explicaciones en ambos idiomas (es_PE y quechua; ADR-0015).

### RF-055: Detección de modificaciones posteriores
- Prioridad: Debe.
- Descripción: en un PDF se distingue qué revisión cubre cada firma y se clasifican los cambios posteriores (permitidos, como formularios o anotaciones, frente a no permitidos). El usuario puede abrir la versión que se firmó.
- Aceptación: se detectan los ataques conocidos sobre firmas PDF (ver AM-05 en el modelo de amenazas).

### RF-056: Validación en el pasado
- Prioridad: Debería. Descripción: se usan los sellos de tiempo y los datos LTV embebidos para validar firmas cuyo certificado ya ha caducado.

## 7. Confianza y red

### RF-060: Almacén de confianza de la IOFE
- Prioridad: Debe. Descripción: berigna incluye su propio conjunto de certificados raíz e intermedios de la IOFE y no depende del almacén del sistema. El usuario puede ver su contenido.
### RF-061: Actualización del almacén de confianza
- Prioridad: Debe. Descripción: el almacén base se actualiza junto con el paquete `.deb`. En tiempo de ejecución se le añaden las CA de la TSL de INDECOPI, verificada contra la raíz de INDECOPI fijada en el paquete; si la TSL no está disponible, no verifica o está vencida, se usa el almacén base (ADR-0014). El usuario puede añadir anclas adicionales, que se marcan como "añadidas por el usuario" en los informes.
### RF-062: Configuración de la TSA
- Prioridad: Debe. Descripción: URL, autenticación opcional (usuario y contraseña, o certificado de cliente), algoritmo de *hash* y tiempo de espera. Incluye un botón "Probar".
### RF-063: OCSP y CRL
- Prioridad: Debe.
- Descripción: OCSP es el mecanismo principal y el único que se usa para firmar y para embeber datos en B-LT y B-LTA. La CRL es solo un respaldo opcional al verificar, desactivado por defecto (`crl-fallback`): la CRL de la CA del DNIe pesa unos 109 MB (SPK-02 §3.2). Si se activa, se muestra su tamaño antes de descargarla y se guarda en caché respetando `nextUpdate`.
- Aceptación: en B-LT se embeben la respuesta OCSP, el certificado del *responder* OCSP y la cadena completa. No se embebe ninguna CRL de la CA del DNIe.
### RF-064: Proxy
- Prioridad: Debería. Descripción: se respeta el proxy del sistema (GNOME/GIO) o uno configurado manualmente.
### RF-065: Funcionamiento sin conexión
- Prioridad: Debe. Descripción: sin red se puede firmar en B-B (con la advertencia de RF-006) y verificar con los datos embebidos.

## 8. Integración con el escritorio

### RF-070: Menú contextual en Nautilus
- Prioridad: Debe. Descripción: las acciones "Firmar con berigna" y "Verificar firma" sobre uno o varios archivos. Si se seleccionan varios, se abre el modo de lote.
### RF-071: Tipos MIME y "Abrir con"
- Prioridad: Debe. Descripción: berigna se registra para `.p7s` y `.p7m`, y aparece como opción secundaria para PDF y XML.
### RF-072: Arrastrar y soltar
- Prioridad: Debe. Descripción: los archivos soltados en la ventana principal se abren para firmarlos o verificarlos (según se detecte si ya llevan firma).
### RF-073: Instancia única
- Prioridad: Debe. Descripción: abrir archivos con la aplicación ya en ejecución los entrega a la instancia existente (`GApplication` con D-Bus).
### RF-074: Extensión de LibreOffice "Firmar con berigna"
- Prioridad: Podría (versión 1.2, decisión del 2026-10-27). Descripción: una extensión de LibreOffice (Python UNO), distribuida en un paquete propio `berigna-libreoffice`, añade la acción "Firmar con berigna". La acción exporta el documento abierto a un PDF y abre berigna con ese archivo; la firma, el PIN y la validación ocurren en berigna, nunca en el proceso de LibreOffice (mismo principio que RNF-SEG-10). Hasta entonces, el flujo es exportar a PDF desde LibreOffice y abrir el archivo en berigna. No se contempla la firma nativa de documentos ODF ni que LibreOffice firme con el DNIe mediante PKCS#11.

## 9. Preferencias, historial y registros

### RF-080: Preferencias
- Prioridad: Debe. Descripción: nivel por defecto, formato por tipo de archivo, sufijo y carpeta de salida, TSA, red, apariencia de la firma visible e idioma de la interfaz (sistema, es_PE o quechua; ver RF-090).
### RF-081: Perfiles de apariencia de la firma visible
- Prioridad: Debería. Descripción: se guardan varios perfiles con nombre (por ejemplo, "Rúbrica" y "Sello institucional").
### RF-082: Historial local de operaciones
- Prioridad: Debería. Descripción: fecha, operación, nombre del archivo, *hash* SHA-256, nivel y resultado. No se guarda el contenido. Se puede borrar.
### RF-083: Registro técnico
- Prioridad: Debe. Descripción: un registro rotativo con niveles (`ERROR`, `WARNING`, `INFO`, `DEBUG`) en `$XDG_STATE_HOME/berigna/logs/` (5 archivos de 1 MB). Nunca incluye el PIN, el contenido del documento ni el DNI completo.

## 10. Idioma y ayuda

### RF-090: Interfaz bilingüe (es_PE y quechua sureño)
- Prioridad: Debe.
- Descripción: la aplicación está disponible completa en español del Perú (es_PE) y en quechua sureño (catálogo `quz`, configuración regional `quz_PE`), según ADR-0011 y ADR-0015. en_US llega en la versión 1.1.
  - Todas las cadenas pasan por gettext. El texto fuente (`msgid`) está en inglés, pero no se muestra en la v1.0.
  - Por defecto se usa el idioma del sistema. Las configuraciones de quechua sureño (`quz`, `quy`, `qu`) muestran el quechua y cualquier otro idioma muestra es_PE.
  - Desde las preferencias se puede forzar es_PE o quechua (se aplica al reiniciar).
  - Las fechas, las horas y los números siguen la configuración regional activa.
  - Cubre la interfaz, los mensajes de error, las explicaciones de verificación, los informes, la extensión de Nautilus, el `.desktop` y la metainfo de AppStream.
- Aceptación:
  1. Ambos catálogos están traducidos al 100 % (`msgfmt --statistics` sin cadenas sin traducir ni marcadas como *fuzzy*).
  2. Con `LANGUAGE=quz_PE` o `LANGUAGE=quy_PE` la interfaz aparece en quechua; con `LANGUAGE=es_MX`, `fr_FR`, `en_US` o `C`, en es_PE.

### RF-091: Manuales y ayuda integrada
- Prioridad: Debe (es evidencia obligatoria de la acreditación: requisito 10 de la guía de INDECOPI, ACR-22).
- Descripción: un manual de usuario y un manual de administración (despliegue, configuración con GSettings y dconf, almacén de confianza), en formato Mallard (ADR-0011), accesibles desde el menú. El manual de usuario se publica en es_PE y en quechua; el de administración, en es_PE (ADR-0015). Ayuda contextual en los errores en el idioma de la interfaz.

### RF-092: Idioma del sello visible
- Prioridad: Debe.
- Descripción: cada perfil de apariencia de la firma visible define el idioma de sus textos fijos (por ejemplo, "Firmado digitalmente por" o su equivalente en quechua) y del formato de la fecha, con independencia del idioma de la interfaz. Por defecto es es_PE.
