# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado semántico.

## [Sin publicar]

### Añadido

Núcleo y DNIe:

- Esqueleto del núcleo `berigna.core` (paquete `src/`, configuración de ruff, mypy estricto y pytest) y umbral de cobertura del 80 % con cobertura de ramas.
- Integración continua en GitHub Actions: `scripts/verificar.sh` en un contenedor Debian 13 con los paquetes de Debian.
- Driver APDU del DNIe v2 (`berigna.core.token.dnie_v2`, ADR-0012): lista blanca estricta por forma de comando (AID, archivos, referencia de PIN, plantilla de MSE, `DigestInfo`) con pruebas de *fuzzing*, lectura del certificado parando en la longitud DER, VERIFY de un solo intento y firma PKCS#1 v1.5 sobre SHA-256/384/512. SELECT y READ BINARY se reintentan de forma acotada ante fallos transitorios; VERIFY y PSO:CDS nunca. `authenticated` y `probe_alive()` para el diagnóstico (RF-007).
- Transporte PC/SC (`berigna.core.token.transport`) con conexión exclusiva y apagado de la tarjeta al cerrar; errores ERR-105 a ERR-108 (tarjeta retirada, en uso por otro programa, servicio PC/SC no disponible, fallo transitorio), de modo que pyscard no llega a las capas superiores.
- Tipo `Pin` que no se muestra, no se serializa y se borra tras usarlo.
- Monitor de lectores y tarjetas en caliente (`berigna.core.token.monitor`, RF-001 y RF-002): sondeo cada 0,5 s sin conectarse a la tarjeta, compatible con una sesión de firma exclusiva.
- Simulador del *applet* PKI del DNIe v2 para las pruebas automatizadas, pruebas HIL de solo lectura y *scripts* manuales con PIN según el protocolo.

Confianza y red:

- Almacén de confianza propio (`berigna.core.trust`, ADR-0009) con las jerarquías ROOT 3 (DNIe) y ROOT 5 (personas jurídicas), verificado contra un manifiesto de huellas al cargarse; anclas del usuario marcadas como tales (RF-060, RF-061). Errores ERR-200 a ERR-202.
- TSL de INDECOPI (`berigna.core.trust.tsl`, ADR-0014): descarga y verificación de la firma con la raíz de INDECOPI fijada en el paquete, vigencia, número de secuencia, uso de clave del firmante y su CRL, probando cada punto de distribución; las CA acreditadas amplían el almacén (incluye ECERNEP PERU CA ROOT 6). Errores ERR-203 y ERR-204.
- Consultas OCSP y CRL comunes (`berigna.core.net.fetchers`): nunca la CRL de un certificado final; las CRL de las CA con un cliente propio que pide primero el espejo principal y el siguiente solo si aquel tarda más de 2 s; conexión de 20 s separada de la lectura y un reintento (R-17). pyhanko-certvalidator 0.26.3 fallaba si cualquier espejo fallaba y guardaba en caché las descargas fallidas.
- Cliente de sellado de tiempo RFC 3161 (`berigna.core.net.tsa`) con comprobación previa y plazo total, también con IPv6 roto.

Firma:

- Validación previa del certificado del firmante antes de pedir el PIN (`berigna.core.validation.check_signer`, RF-006): vigencia, cadena hasta una raíz de la IOFE, uso de no repudio y revocación (OCSP para el certificado, nunca su CRL de 109 MB; CRL para las CA intermedias). Sin datos de revocación, la firma queda limitada a B-B y `SignerCheck.revocation_note` dice por qué. Errores ERR-210 a ERR-214. Verificada con un certificado real del DNIe contra el OCSP y las ARL de RENIEC.
- Firma PAdES B-B, B-T, B-LT y B-LTA (`berigna.core.formats.pades`, pyHanko 0.25.1) con la operación de clave privada en el chip; firmas sucesivas por actualización incremental (RF-014); motivo, ubicación y contacto (RF-013). Si tras la firma falla la incorporación de datos de validación o el sello de documento, se conserva la firma y el resultado indica el nivel alcanzado y el motivo.
- Orquestación de la firma (`berigna.core.signing.sign_pdf_file`): el archivo debe seguir siendo el previsualizado y ser un PDF firmable (RF-018); certificado validado, nivel disponible y TSA comprobada antes del PIN (RF-006); cancelación sin enviar el PIN; escritura atómica que nunca sobrescribe (RF-045). Errores ERR-300 a ERR-306.

Verificación e informes:

- Verificador de firmas PDF (`berigna.core.validation.verify_pdf`, RF-050, RF-055, RF-056): indicación y subindicación de ETSI EN 319 102-1 con el proceso básico y, para las firmas con sello, con el de validación a largo plazo, de modo que una firma cuyo certificado ya venció sigue siendo válida si un sello prueba que existía antes. Datos de revocación embebidos (DSS y `revocationInfoArchival` de las firmas heredadas `adbe.pkcs7.detached`), revisión firmada, clasificación de los cambios posteriores, sellos de firma y de documento con su propia indicación, y subindicaciones precisas donde pyHanko da una genérica. SHA-1, MD5 y RSA de menos de 2048 bits no se aceptan, con una política propia escrita en `berigna.core.validation.algorithms` que también aplica la validación previa a la clave del firmante (ACR-18). Errores ERR-400 y ERR-401.
- Explicaciones en lenguaje llano de cada indicación y subindicación ETSI y de cada código de error (`berigna.core.report`, RF-053), e informes de verificación en JSON y en PDF (RF-054); el PDF es reproducible byte a byte. Del DNI y del RUC de los firmantes solo se muestran las cuatro últimas cifras.
- Infraestructura de traducción con GNU gettext (`po/`, `scripts/traducciones.sh`, `berigna.core.i18n`): catálogo es_PE completo y catálogo de quechua sureño a la espera de los traductores; el quechua pendiente se muestra en es_PE, nunca en el texto fuente inglés (ADR-0015).
- Matriz de validación externa PAdES por niveles contra DSS 6.2 (`tests/interop/`, `docs/07-calidad/validacion-externa-fase2.md`).

Interfaz (Fase 3):

- Aplicación GTK 4 y libadwaita `com.noggalito.Berigna` construida con Meson (ADR-0010): vistas en Blueprint, recursos, esquema de GSettings, catálogos con alias `quy` y `qu`, y lanzador. `scripts/ejecutar.sh` la lanza desde el árbol de trabajo.
- Ventana principal: abrir un documento con el botón, arrastrándolo o como argumento; estado del lector y del DNIe en la barra inferior.
- `berigna.core.documents`: tipo de documento, páginas, firmas y SHA-256 al abrirlo.
- Las vistas se traducen con `core.i18n` y no con el gettext de C, que mostraba el inglés con la configuración regional C; el idioma cambia sin reiniciar.
- Aviso de traducción sin revisar con la interfaz en quechua, con el botón "Ver en español" (DP-14); también en el informe PDF en quechua.
- Verificación de PDF firmados (CU-06): resumen global, una tarjeta por firma con su explicación y sus detalles técnicos, sellos de documento, "Verificar de nuevo" si algún resultado es indeterminado, exportación del informe (PDF en español o en quechua, y JSON) y de la versión que dejó cada firma. Cada página tiene su barra de título con el botón de volver.
- Firma visible (CU-02, ADR-0018): solo texto, rúbrica o logotipo precargados, o código QR con los datos de la firma y la dirección para verificarla; recuadro que se dibuja y se mueve sobre la vista previa, con el sello en vivo; tipografías de la marca (Source Sans 3 y Arvo) incrustadas; idioma del sello independiente del de la interfaz (RF-092). Preferencias → Firma visible: valores por defecto e imágenes, guardadas sin metadatos. ERR-308 antes del PIN si el sello no se puede dibujar.
- Ayuda contextual (ADR-0017): botón "Más información" junto al nivel de firma, el algoritmo de *hash*, la TSA, el tiempo de espera, el proxy y la lista de confianza, que abre `https://berigna.noggalito.com/ayuda/<versión>/<idioma>/<tema>`.
- Preferencias (CU-08): idioma, nivel por defecto, algoritmo de *hash*, sufijo y carpeta de los archivos firmados; TSA con el botón "Probar"; tiempo de espera; proxy del sistema, manual o ninguno (RF-064); estado de la TSL de INDECOPI con "Actualizar ahora".
- TSL de INDECOPI en uso (ADR-0014, RF-061): se comprueba al arrancar si la guardada tiene más de un día y sus CA amplían el almacén; caché en `~/.local/share/berigna/tsl/` con el número de secuencia aceptado, que impide volver a una lista anterior (`core.trust.cache`).
- `core.net.proxy`: el proxy configurado se aplica a todas las peticiones HTTP, también a las de pyhanko-certvalidator. `core.files.write_atomically` sustituye a `core.signing.write_atomically`, que sigue disponible.
- Icono de la aplicación a partir del isotipo de la marca: escalable, una variante con el símbolo reducido para 16 a 32 px y la versión simbólica; se instala en `hicolor` y va en los recursos.
- Firma de PDF (CU-01, CU-03): vista previa con Poppler (ADR-0016), nivel (los que necesitan una TSA, desactivados mientras no haya una), motivo y ubicación; diálogo del PIN con el resumen, el DNI enmascarado y los intentos restantes; resultado con "Abrir", "Mostrar en la carpeta" y "Verificar"; ofrece firmar en B-B si la revocación no se pudo comprobar. Firmar encima de un PDF ya firmado avisa si alguna firma existente no es válida.
- `core.signing.output_path`: el nombre del archivo firmado se numera si ya existe, sin sobrescribir nunca (RF-045).
- ERR-307: un documento certificado por su autor sin cambios permitidos (DocMDP) se rechaza antes del PIN; `inspect_document` lo indica (`locked`).
- Plan de mantenimiento (`docs/11-mantenimiento/plan-de-mantenimiento.md`, BRG-MAN-001): versiones y ramas, hechos externos que obligan a publicar, vigilancia automática, proceso de cada versión, seguridad, incidencias y continuidad.
- Traducción completa al quechua sureño (Cusco-Collao): 388 mensajes de la interfaz, del sello y de los informes, hecha con IA y el glosario `docs/06-ux/glosario-quechua.md` (BRG-UX-003), sin revisar por hablantes (DP-14); el aviso de traducción sin revisar y "Ver en español" se mantienen. Una sola forma plural (`nplurals=1`). "berigna" va en negrita también con sufijos quechuas ("berignaqa").
- Protocolo de la prueba de usabilidad (`docs/07-calidad/prueba-de-usabilidad.md`, BRG-CAL-005): participantes, tareas, seguridad del PIN, consentimiento, cuestionario SUS en español y en quechua, registro y criterio de aceptación.
- Historial de operaciones (RF-082; `core.history`): firmas, firmas de lote y verificaciones con fecha, nombre, SHA-256 del original y del firmado, nivel, firmante (DNI enmascarado) y resultado; búsqueda, exportación a CSV y borrado; SQLite con permisos 0600. Se desactiva o se le pide la ruta completa en Preferencias → General.
- Preferencias → Confianza → Certificados de confianza (RF-060): los certificados con que se comprueban las firmas, por origen, con su vigencia y su SHA-256.
- Diagnóstico (CU-07, RF-007; `core.diagnostics`): servicio `pcscd`, lector, tarjeta, certificado de firma (con aviso de vencimiento), confianza y revocación en línea, y TSA, con una acción sugerida por paso e informe copiable sin PIN y con el DNI enmascarado. Desde el menú y desde los errores de lector, tarjeta o certificado.
- Registro técnico rotativo (RF-083; `core.logs`): `~/.local/state/berigna/logs/berigna.log`, 5 archivos de 1 MB, con los números de cinco o más cifras enmascarados también en las trazas; DEBUG con `BERIGNA_DEBUG=1`.
- Firma por lotes de PDF (CU-04, RF-040 a RF-043; `core.batch`): un solo PIN para todos los documentos, lista que se confirma antes del PIN, un error en un archivo no detiene los demás, cancelación entre archivos, nombres de salida que no chocan e informe CSV (`core.report.batch_report`). Se abre con "Firmar varios documentos…" o abriendo o arrastrando varios archivos o una carpeta. ERR-309 para los archivos que quedan sin firmar al cancelar.
- Entrada de escritorio `com.noggalito.Berigna.desktop` (nombre, descripción y palabras clave traducidas; abre PDF), validada con `desktop-file-validate` en `meson test`. `scripts/escritorio.sh` la instala con los iconos en `~/.local/share` para el árbol de desarrollo, de modo que GNOME muestra el icono de berigna en el Dock.

### Cambiado

- Los CSV del historial y del lote se proponen con la fecha y la hora delante: "2026-10-29_00h55_historial-berigna.csv".
- Antes de firmar, el diálogo del PIN avisa si el certificado de firma vence en menos de un mes, con la fecha y dónde renovarlo (Ciudadano Digital).
- Vista previa: arrastrar la página la desplaza (con zoom); el recuadro de la firma se mueve arrastrándolo y cambia de tamaño con el tirador de su esquina inferior derecha, en lugar de dibujarse de nuevo.
- Respuesta de RENIEC (2026-10-28): el PIN bloqueado se desbloquea en Ciudadano Digital o en una agencia (ERR-111); los certificados del DNIe duran cuatro años, aunque el DNI siga vigente, y se renuevan en Ciudadano Digital (ERR-211). El validador de referencia es Firma Perú, porque RENIEC ya no distribuye ReFirma a terceros.
- Almacén de confianza: las huellas de las seis anclas coinciden con el repositorio oficial de RENIEC; se añade la "ECEP-RENIEC CA Class 3" de la jerarquía ROOT 3 (2024), que el repositorio publica y la TSL de INDECOPI no incluye, para que se puedan verificar los certificados que emite aunque el PDF no traiga esa intermedia.
- Titular del proyecto: noggalito (DP-05). Cabeceras de licencia, metadatos del paquete, catálogos y "Acerca de" pasan de "Calú" a "noggalito"; el sitio de "Acerca de" es <https://berigna.noggalito.com> y las incidencias siguen en GitHub. Contacto único: `berigna@noggalito.com` (también en `SECURITY.md`, junto con los avisos privados de GitHub).
- Identificador de la aplicación: `com.noggalito.Berigna` en lugar de `pe.berigna.Berigna` (ADR-0019), con su ruta de GSettings `/com/noggalito/Berigna/`. La configuración guardada con el identificador anterior no se migra; `scripts/escritorio.sh` borra la integración anterior.
- Debian oficial desde la v1.0 (ADR-0020, modifica ADR-0006).
- Vista previa de la firma: número de página que se escribe para saltar a ella y zoom (botones, Ctrl + rueda, "Ajustar") del 50 % al 400 %; con zoom, la vista lleva al recuadro de la firma. Sigue abriéndose en la primera página; al activar la firma visible pasa a la última.
- La firma visible se elige en una sola lista que empieza por "No visible", en el panel de firma y en Preferencias, en lugar de un interruptor y una lista. En un recuadro más alto que ancho, la imagen o el QR van encima del texto (orientación vertical automática).
- Motivo "Por encargo" en la lista.
- El motivo se elige de una lista (autoría, conformidad, visto bueno, aprobación) con "Otro motivo…", y se escribe en el idioma de la firma (`core.reasons`); la ubicación, de las cinco últimas usadas o "Otra ubicación…". Claves nuevas: `signature-reason-kind` y `recent-locations`.
- Preferencias → Firma visible → "DNI en la firma": últimos cuatro dígitos (por defecto), completo o no mostrar, para el sello y su QR (clave `appearance-dni`).
- "berigna" va en negrita en todos los mensajes de la interfaz y en el pie del informe PDF. Los mensajes con formato se escapan, así que un nombre de archivo o de firmante con `&` o `<` ya no rompe el texto.
- Fechas y horas con la fecha ISO 8601, la hora con el símbolo h del SI y el desfase respecto de UTC, en la hora local: "2026-10-28 a las 18h47 UTC-5". Se aplica al sello visible, al QR, a la verificación y al informe PDF; el informe JSON sigue en ISO 8601 y UTC.
- "Versión firmada" empieza con mayúscula ("Primeros … bytes del archivo"); en Preferencias → Firma visible, "berigna" va en negrita.
- El historial indica "revocación no comprobada" en las firmas hechas sin poder consultar la revocación del certificado (RF-006).
- El historial anota también los documentos de un lote que quedaron sin firmar al cancelarlo o detenerse (ERR-309).
- Al añadir documentos a un lote, se leen y se calcula su SHA-256 en segundo plano: una carpeta con muchos PDF grandes ya no congela la ventana. "Firmar" espera a que la lista esté completa.
- Volver a abrir el historial o el diagnóstico desde el menú lleva a la página ya abierta, en lugar de apilar otra igual.

### Corregido

- Un PDF con una firma cuyo CMS rompe pyHanko o asn1crypto después del resumen (datos de revocación de Adobe, sello de la firma o diagnóstico de la cadena) daba "error inesperado"; ahora es TOTAL-FAILED/FORMAT_FAILURE, como el resto de firmas malformadas. Lo mismo con los sellos de documento.
- Cambiar el idioma con el diálogo del PIN abierto destruía la ventana y podía dejar el hilo de firma esperando para siempre con la tarjeta reservada. Ahora el diálogo se cancela antes (no se envía el PIN).
- En un lote, un error que berigna no conoce detenía todos los documentos y el informe no llegaba a crearse; ahora falla solo ese documento (ERR-000) y los demás siguen (RF-043).
- Más errores de pyHanko al abrir un PDF malformado se muestran como ERR-304 antes del PIN; una tarjeta retirada justo al conectar da ERR-105, y un fallo de la TSA distinto de los habituales se muestra con su causa y no como "no respondió en 30 s".
- El historial no cerraba su conexión con la base de datos si una operación fallaba.
- Abrir Preferencias con el diálogo ya abierto ponía otro encima; ahora se muestra el mismo. La prueba de la TSA y "Actualizar ahora" ya no tocan el diálogo si se cerró mientras esperaban, y dos actualizaciones de la TSL (la del arranque y la manual) ya no escriben a la vez en la caché.
- Un PDF cuya cabecera empieza en los últimos bytes del primer kilobyte se trataba como "otro tipo de archivo".
- Soltar varios archivos que no están en el equipo no avisaba de nada; ahora da el mismo aviso que con uno.
- Si faltan las vistas compiladas (`BERIGNA_RESOURCES` apunta a un archivo que no existe), berigna lo dice en una línea en lugar de una traza.
- La rúbrica y el logotipo precargados se guardaban con los permisos de cualquier archivo nuevo; ahora solo los puede leer su dueño (0600, y su carpeta 0700), como el historial.
- Los botones que solo tienen icono (exportar, borrar, zoom, volver…) no tenían nombre para los lectores de pantalla; ahora lo toman de su descripción emergente (RNF-USA-03).
- Las pruebas de la interfaz heredaban el idioma de la anterior: una que cambiaba a quechua dejaba el quechua a las siguientes (no se notaba mientras el catálogo estaba vacío). Cada prueba empieza ahora en es_PE.
- Las pruebas que arrancan berigna sin rutas propias escribían en el historial real del usuario (`~/.local/share/berigna/`): GLib guarda la carpeta de datos la primera vez que se le pregunta. berigna la lee ahora del entorno (`core.files.data_directory`) y las pruebas usan una carpeta temporal.
- El diagnóstico daba "No se pudo consultar a RENIEC si tu certificado está revocado" con la red funcionando: validaba con la hora fijada, y la tolerancia de 1 s rechazaba la respuesta OCSP de RENIEC por "demasiado reciente"; ahora valida "ahora", con la tolerancia de 5 minutos. El motivo de una revocación no comprobada queda en el registro técnico, igual que cada paso del diagnóstico que no sale bien.
- Las pruebas que arrancan berigna escribían el registro técnico en `~/.local/state` del usuario; ahora usan una carpeta temporal.
- Los archivos firmados, los informes exportados y el CSV del lote se creaban con permisos `rw-------` (los de un archivo temporal); ahora tienen los de cualquier archivo nuevo según la máscara del usuario, y al reemplazar uno existente se conservan los suyos.
- No se podía firmar un PDF cuyos metadatos había borrado ExifTool: el tráiler seguía apuntando a un `/Info` liberado y pyHanko fallaba al escribir la fecha de modificación, después del PIN, con "Error inesperado". La revisión de la firma lleva ahora un `/Info` nuevo. Los errores internos de pyHanko con PDF malformados se muestran como ERR-304.
- Mover el sello de la firma visible era lento con el QR: la página y el sello se dibujan ahora una vez por tamaño y se guardan como imagen.
- El QR de la firma visible no declaraba su codificación y algunos lectores de teléfono mostraban "Cómo" como "C髇o". Ahora lleva el indicador ECI de UTF-8 antes de los datos.
- En Preferencias, el valor de las listas desplegables se cortaba ("Validación a largo plazo (…"), también al desplegarlas; ahora va completo como subtítulo y las opciones se ajustan en varias líneas.
- Una excepción inesperada en el hilo de verificación o de firma dejaba la interfaz esperando para siempre; ahora se muestra como error inesperado (ERR-000) y se registra.
- Las pruebas de la interfaz abrían sus ventanas en el escritorio del usuario en una sesión Wayland: GTK prefería `WAYLAND_DISPLAY` a la pantalla virtual de `xvfb-run`. Ahora usan solo X11 sobre Xvfb. Una prueba nueva comprueba que el núcleo no importa GTK ni la interfaz (RNF-MAN-01).
- La verificación y la validación previa "en este momento" rechazaban como "demasiado reciente" una respuesta OCSP producida mientras se esperaba al servicio: la tolerancia de pyhanko-certvalidator es de 1 s y RENIEC tarda segundos (R-17). Un PDF firmado con el DNIe real salía INDETERMINATE / TRY_LATER y la firma quedaba limitada a B-B. Ahora la tolerancia es de 5 minutos al validar en el momento actual; la validación en una fecha pasada no cambia.

Proyecto:

- Logotipos SVG de la identidad visual (`data/brand/`), bajo GPL-3.0-or-later como el resto del proyecto.
- Dependencias declaradas en `pyproject.toml`, alineadas con las versiones de Debian 13.
- Idiomas de la versión 1.0: español del Perú y quechua sureño (ADR-0015); el inglés pasa a la versión 1.1.
- Plan de compatibilidad: DNIe 1.0 y DNIe 3.0 previstos para la versión 1.1 (investigación SPK-06).
- Requisito RF-074: extensión de LibreOffice "Firmar con berigna", prevista para la versión 1.2.
- Cabeceras SPDX en los logotipos, la entrada de escritorio y el `pom.xml` de SPK-03; una prueba exige que los catálogos es_PE y quechua estén completos.
- Protocolo de la prueba de usabilidad: pasos para instalar berigna desde el código fuente en el equipo de la prueba, fijados a la versión candidata `v0.3.0-rc.1`.
- Recomendaciones a futuro sobre la práctica de desarrollo (`docs/08-desarrollo/recomendaciones-a-futuro.md`, BRG-DES-002): vigilancia, SBOM, pruebas por propiedades, proceso de versión, rendimiento, paquete reproducible y registro local de fallos; sin informes de fallos remotos.
- Revisión general de la documentación: módulos del núcleo en la arquitectura, glosario, requisitos RF-002, RF-053 y RF-090, dependencias del empaquetado y estado del proyecto.
- Segunda revisión: Firma Perú como validador de referencia en la estrategia de pruebas (PR-INT-01, PR-INT-05) y en el README; PR-I18N-05 con el cambio de idioma al momento; ubicaciones de datos reales (`apariencia/`, `tsl/`) y las previstas marcadas como tales; CU-02 y CU-04 según la interfaz actual; política de fronteras con las bibliotecas en BRG-DES; regla de Fecha y Versión en las convenciones y cabeceras sincronizadas. `spikes/` queda fuera de `ruff`.
- Consentimiento de la prueba de usabilidad conforme a la Ley N.° 29733: responsable, finalidad, plazos de conservación, derechos y grabación opcional.
