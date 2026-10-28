# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado semántico.

## [Sin publicar]

### Añadido

- Esqueleto del núcleo `berigna.core` (paquete `src/`, configuración de ruff, mypy estricto y pytest).
- Driver APDU del DNIe v2 (`berigna.core.token.dnie_v2`, ADR-0012): lista blanca de instrucciones, lectura del certificado parando en la longitud DER, VERIFY de un solo intento, firma PKCS#1 v1.5 sobre SHA-256/384/512.
- Transporte PC/SC (`berigna.core.token.transport`) con conexión exclusiva y apagado de la tarjeta al cerrar.
- Tipo `Pin` que no se muestra, no se serializa y se borra tras usarlo.
- Simulador del *applet* PKI del DNIe v2 para las pruebas automatizadas, y pruebas HIL de solo lectura.
- Lista blanca estricta por forma de comando (AID, archivos, referencia de PIN, plantilla de MSE, `DigestInfo`), con pruebas de *fuzzing*.
- Errores ERR-105 (tarjeta retirada), ERR-106 (tarjeta en uso por otro programa), ERR-107 (servicio PC/SC no disponible) y ERR-108 (fallo transitorio): pyscard ya no llega a las capas superiores.
- Reintento acotado de SELECT y READ BINARY ante fallos transitorios tras el apagado de la tarjeta; VERIFY y PSO:CDS no se reintentan nunca.
- `DnieV2Token.authenticated` y `DnieV2Token.probe_alive()` para el diagnóstico (RF-007).
- Umbral de cobertura del 80 % con cobertura de ramas.
- Logotipos SVG de la identidad visual (`data/brand/`), bajo GPL-3.0-or-later como el resto del proyecto.
- Almacén de confianza propio (`berigna.core.trust`, ADR-0009) con las jerarquías ROOT 3 (DNIe) y ROOT 5 (personas jurídicas), verificado contra un manifiesto de huellas al cargarse; anclas del usuario marcadas como tales (RF-060, RF-061). Errores ERR-200 a ERR-202.
- Validación previa del certificado del firmante antes de pedir el PIN (`berigna.core.validation.check_signer`, RF-006): vigencia, cadena hasta una raíz de la IOFE, uso de no repudio y revocación (OCSP para el certificado, nunca su CRL de 109 MB; CRL para las CA intermedias). Sin datos de revocación, la firma queda limitada a B-B. Errores ERR-210 a ERR-214. Verificada con un certificado real del DNIe contra el OCSP y las ARL de RENIEC (0,96 s).
- Monitor de lectores y tarjetas en caliente (`berigna.core.token.monitor`, RF-001 y RF-002): sondeo cada 0,5 s sin conectarse a la tarjeta, compatible con una sesión de firma exclusiva.
- Firma PAdES B-B (`berigna.core.formats.pades`, pyHanko 0.25.1) con la operación de clave privada en el chip; firmas sucesivas por actualización incremental (RF-014); motivo, ubicación y contacto (RF-013); SHA-256/384/512.
- Orquestación de la firma (`berigna.core.signing.sign_pdf_file`): el archivo debe seguir siendo el previsualizado (RF-018), validación del certificado antes del PIN (RF-006), cancelación sin enviar el PIN, escritura atómica que nunca sobrescribe (RF-045). Errores ERR-300 a ERR-304.
- Un PDF que no se puede firmar se rechaza antes de pedir el PIN.
- `SignerCheck.revocation_note` indica por qué no se pudo comprobar la revocación (sin red o sin respuesta del servicio), para que la interfaz elija el aviso.
- Dependencias pyHanko, pyhanko-certvalidator y asn1crypto declaradas en `pyproject.toml`, alineadas con las versiones de Debian 13.
- Firma PAdES B-T, B-LT y B-LTA (`sign_pdf_file(level=..., timestamper=...)`): antes del PIN se exige revocación comprobada y una TSA que responda. Si tras la firma falla la incorporación de datos de validación o el sello de documento, se conserva la firma y el resultado indica el nivel alcanzado y el motivo. Errores ERR-305 (TSA) y ERR-306 (nivel no disponible).
- Cliente de sellado de tiempo RFC 3161 (`berigna.core.net.tsa`) con comprobación previa y plazo total, también con IPv6 roto.
- Consultas OCSP y CRL comunes (`berigna.core.net.fetchers`): un reintento ante fallo (R-17) y nunca la CRL de un certificado final.
- Subindicaciones de ETSI precisas en la verificación: la falta de datos de revocación (`TRY_LATER`) y un certificado vencido en la cadena (`OUT_OF_BOUNDS_NO_POE`) ya no se informan con la subindicación genérica de pyHanko.
- Infraestructura de traducción con GNU gettext (`po/`, `scripts/traducciones.sh`, `berigna.core.i18n`): catálogo es_PE completo y catálogo de quechua sureño a la espera de los traductores; el quechua pendiente se muestra en es_PE, nunca en el texto fuente inglés (ADR-0015).
- Explicaciones en lenguaje llano de cada indicación y subindicación ETSI y de cada código de error (`berigna.core.report`, RF-053), e informe de verificación JSON con explicaciones en ambos idiomas (RF-054). Del DNI del firmante solo se conservan los cuatro últimos dígitos.
- Plan de compatibilidad: DNIe 1.0 y DNIe 3.0 previstos para la versión 1.1 (investigación SPK-06).
- Idiomas de la versión 1.0: español del Perú y quechua sureño (ADR-0015); el inglés pasa a la versión 1.1.
- Requisito RF-074: extensión de LibreOffice "Firmar con berigna", prevista para la versión 1.2.
- Verificador de firmas PDF (`berigna.core.validation.verify_pdf`, primer incremento de la Fase 2): indicación y subindicación de ETSI EN 319 102-1 con el proceso básico, datos de revocación embebidos (DSS y `revocationInfoArchival` de las firmas heredadas `adbe.pkcs7.detached`), revisión firmada y clasificación de los cambios posteriores (RF-055). Errores ERR-400 y ERR-401.
- Verificación de sellos de tiempo: las firmas B-T, B-LT y B-LTA se validan con el proceso de ETSI para material de validación a largo plazo, de modo que una firma cuyo certificado ya venció sigue siendo válida si un sello prueba que existía antes (RF-056). Cada sello de firma y de documento tiene su propia indicación (RF-053). `verify_pdf` acepta además respuestas OCSP y CRL aportadas por quien llama.

### Corregido

- Consultas de revocación a RENIEC que daban INDETERMINATE/TRY_LATER sin motivo (R-17): las CRL de las CA se descargan con un cliente propio que se queda con el primer espejo que responde y solo pide el siguiente si el anterior tarda más de 2 s, y el tiempo de conexión es de 20 s, separado del de lectura. pyhanko-certvalidator 0.26.3 fallaba si cualquier espejo fallaba y guardaba en caché las descargas fallidas.
