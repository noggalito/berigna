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
- Plan de compatibilidad: DNIe 1.0 y DNIe 3.0 previstos para la versión 1.1 (investigación SPK-06).
- Requisito RF-074: extensión de LibreOffice "Firmar con berigna", prevista para la versión 1.2.
