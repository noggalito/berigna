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

- Aplicación GTK 4 y libadwaita `pe.berigna.Berigna` construida con Meson (ADR-0010): vistas en Blueprint, recursos, esquema de GSettings, catálogos con alias `quy` y `qu`, y lanzador. `scripts/ejecutar.sh` la lanza desde el árbol de trabajo.
- Ventana principal: abrir un documento con el botón, arrastrándolo o como argumento; estado del lector y del DNIe en la barra inferior.
- `berigna.core.documents`: tipo de documento, páginas, firmas y SHA-256 al abrirlo.
- Las vistas se traducen con `core.i18n` y no con el gettext de C, que mostraba el inglés con la configuración regional C; el idioma cambia sin reiniciar.
- Aviso de traducción sin revisar con la interfaz en quechua, con el botón "Ver en español" (DP-14); también en el informe PDF en quechua.
- Verificación de PDF firmados (CU-06): resumen global, una tarjeta por firma con su explicación y sus detalles técnicos, sellos de documento, "Verificar de nuevo" si algún resultado es indeterminado, exportación del informe (PDF en español o en quechua, y JSON) y de la versión que dejó cada firma. Cada página tiene su barra de título con el botón de volver.
- Preferencias (CU-08): idioma, nivel por defecto, algoritmo de *hash*, sufijo y carpeta de los archivos firmados; TSA con el botón "Probar"; tiempo de espera; proxy del sistema, manual o ninguno (RF-064); estado de la TSL de INDECOPI con "Actualizar ahora".
- TSL de INDECOPI en uso (ADR-0014, RF-061): se comprueba al arrancar si la guardada tiene más de un día y sus CA amplían el almacén; caché en `~/.local/share/berigna/tsl/` con el número de secuencia aceptado, que impide volver a una lista anterior (`core.trust.cache`).
- `core.net.proxy`: el proxy configurado se aplica a todas las peticiones HTTP, también a las de pyhanko-certvalidator. `core.files.write_atomically` sustituye a `core.signing.write_atomically`, que sigue disponible.
- Icono de la aplicación a partir del isotipo de la marca: escalable, una variante con el símbolo reducido para 16 a 32 px y la versión simbólica; se instala en `hicolor` y va en los recursos.
- Firma de PDF (CU-01, CU-03): vista previa con Poppler (ADR-0016), nivel (los que necesitan una TSA, desactivados mientras no haya una), motivo y ubicación; diálogo del PIN con el resumen, el DNI enmascarado y los intentos restantes; resultado con "Abrir", "Mostrar en la carpeta" y "Verificar"; ofrece firmar en B-B si la revocación no se pudo comprobar. Firmar encima de un PDF ya firmado avisa si alguna firma existente no es válida.
- `core.signing.output_path`: el nombre del archivo firmado se numera si ya existe, sin sobrescribir nunca (RF-045).
- ERR-307: un documento certificado por su autor sin cambios permitidos (DocMDP) se rechaza antes del PIN; `inspect_document` lo indica (`locked`).

### Corregido

- Una excepción inesperada en el hilo de verificación o de firma dejaba la interfaz esperando para siempre; ahora se muestra como error inesperado (ERR-000) y se registra.
- Las pruebas de la interfaz abrían sus ventanas en el escritorio del usuario en una sesión Wayland: GTK prefería `WAYLAND_DISPLAY` a la pantalla virtual de `xvfb-run`. Ahora usan solo X11 sobre Xvfb. Una prueba nueva comprueba que el núcleo no importa GTK ni la interfaz (RNF-MAN-01).
- La verificación y la validación previa "en este momento" rechazaban como "demasiado reciente" una respuesta OCSP producida mientras se esperaba al servicio: la tolerancia de pyhanko-certvalidator es de 1 s y RENIEC tarda segundos (R-17). Un PDF firmado con el DNIe real salía INDETERMINATE / TRY_LATER y la firma quedaba limitada a B-B. Ahora la tolerancia es de 5 minutos al validar en el momento actual; la validación en una fecha pasada no cambia.

Proyecto:

- Logotipos SVG de la identidad visual (`data/brand/`), bajo GPL-3.0-or-later como el resto del proyecto.
- Dependencias declaradas en `pyproject.toml`, alineadas con las versiones de Debian 13.
- Idiomas de la versión 1.0: español del Perú y quechua sureño (ADR-0015); el inglés pasa a la versión 1.1.
- Plan de compatibilidad: DNIe 1.0 y DNIe 3.0 previstos para la versión 1.1 (investigación SPK-06).
- Requisito RF-074: extensión de LibreOffice "Firmar con berigna", prevista para la versión 1.2.
