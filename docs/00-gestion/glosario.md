# Glosario

| Campo | Valor |
|---|---|
| Documento | BRG-GES-002 |
| Versión | 0.1.1 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

| Término | Definición |
|---|---|
| AAC | Autoridad Administrativa Competente de la IOFE. En el Perú, este rol lo cumple INDECOPI. |
| AdES | *Advanced Electronic Signatures*: familia de formatos de firma avanzada de ETSI (CAdES, PAdES, XAdES, JAdES). |
| AIA | *Authority Information Access*: extensión X.509 que indica dónde obtener el certificado emisor y el servicio OCSP. |
| APDU | *Application Protocol Data Unit*: unidad de comunicación entre el lector y la tarjeta inteligente (ISO/IEC 7816-4). |
| ATR | *Answer To Reset*: secuencia de bytes que la tarjeta devuelve al energizarse; sirve para identificar el modelo de chip. |
| B-B, B-T, B-LT, B-LTA | Niveles de línea base de las firmas AdES. B-B: firma básica. B-T: con sello de tiempo de la firma. B-LT: con los datos de validación (certificados, OCSP y CRL) embebidos. B-LTA: con sellos de tiempo de archivo que protegen todo lo anterior a largo plazo. |
| CAdES | *CMS Advanced Electronic Signatures* (ETSI EN 319 122). Firma de cualquier archivo en formato CMS/PKCS#7 (`.p7s` separada, `.p7m` envuelta). |
| CCID | *Chip Card Interface Device*: clase USB estándar para lectores de tarjeta; en Linux la implementa `libccid`. |
| CRL | *Certificate Revocation List*: lista de certificados revocados publicada por una entidad de certificación. |
| DNIe | Documento Nacional de Identidad electrónico del Perú, emitido por RENIEC. Su chip contiene certificados digitales y las claves privadas asociadas. |
| DNIe 1.0 | Primera generación del DNIe (desde 2013), con chip Oberthur y aplicación IAS-ECC. Prevista en la versión 1.1 de berigna (SPK-06). |
| DNIe v2 | Segunda generación del DNIe, con un chip NXP JCOP3 (Java Card), un *applet* PKI con tres certificados (firma, autenticación y cifrado) y un *applet* ICAO eMRTD. OpenSC no lo soporta (SPK-01). |
| DNIe 3.0 | Generación presentada en abril de 2025 y única emitida desde agosto de 2025. Chip por identificar (SPK-06); prevista en la versión 1.1. |
| DocMDP | *Document Modification Detection and Prevention*: firma de certificación de un PDF que define qué cambios se permiten después de firmar. |
| ECEP-RENIEC | Entidad de Certificación para el Estado Peruano, operada por RENIEC. Su CA subordinada "ECEP-RENIEC CA Class 2 II" emite los certificados del DNIe v2 (verificado en SPK-01). |
| ECERNEP | Entidad de Certificación Nacional para el Estado Peruano: raíz de la jerarquía del Estado. Raíz del DNIe v2: "ECERNEP PERU CA ROOT 3". Existe también una "Root 5". `[VERIFICAR]` qué entidad opera actualmente cada raíz (consulta CE-08). |
| JCOP | *Java Card OpenPlatform*: sistema operativo de tarjetas inteligentes de NXP. |
| ETSI | *European Telecommunications Standards Institute*; publica los estándares AdES que adoptan muchas infraestructuras de firma, entre ellas la IOFE. |
| Firma digital | En la legislación peruana, firma electrónica que usa criptografía asimétrica, basada en un certificado emitido dentro de la IOFE, y que tiene la misma validez y eficacia jurídica que la firma manuscrita. |
| gettext | Sistema estándar de traducción de software (GNU). Extrae las cadenas marcadas con `_()` y las traduce mediante catálogos `.po` / `.mo`. |
| i18n / l10n | Internacionalización (preparar el software para varios idiomas) y localización (traducirlo y adaptarlo a un idioma o región concretos). |
| IOFE | Infraestructura Oficial de Firma Electrónica del Perú. |
| *Locale* (configuración regional) | Combinación de idioma y región (por ejemplo, `es_PE` o `quz_PE`) que determina los textos y el formato de fechas y números. |
| Quechua sureño | Rama del quechua hablada en el sur del Perú (variedades cusco-collao, `quz`, y ayacucho-chanka, `quy`). Segundo idioma de berigna 1.0 (ADR-0015). No confundir con el kichwa amazónico (`qvs`, `qvo`). |
| LTV | *Long Term Validation*: capacidad de validar una firma años después, cuando los certificados ya caducaron o los servicios de revocación ya no responden. |
| Middleware | Software que traduce entre una aplicación y la tarjeta (por ejemplo, OpenSC). Expone una interfaz PKCS#11. |
| Módulo PKCS#11 | Biblioteca compartida (`.so`) que implementa la API PKCS#11 para un *token* concreto. |
| No repudio | Uso de clave (`nonRepudiation`/`contentCommitment`) que identifica el certificado destinado a firmar con valor legal, a diferencia del de autenticación. |
| OCSP | *Online Certificate Status Protocol* (RFC 6960): consulta en línea del estado de revocación de un certificado. |
| PAdES | *PDF Advanced Electronic Signatures* (ETSI EN 319 142). Firma embebida dentro del propio PDF. |
| PC/SC | Estándar de acceso a lectores de tarjetas inteligentes; en Linux lo implementa el demonio `pcscd` (pcsc-lite). |
| PIN | Código personal que desbloquea el uso de la clave privada en el chip del DNIe. |
| PIN pad | Lector con teclado propio, en el que el PIN se teclea sin pasar por el computador. |
| PKCS#11 | Estándar (OASIS) de API para acceder a dispositivos criptográficos (*Cryptoki*). |
| ReFirma | Software oficial de firma digital de RENIEC. Sirve como referencia de interoperabilidad. |
| RENIEC | Registro Nacional de Identificación y Estado Civil del Perú. |
| SoftHSM | Implementación de PKCS#11 por software; se usa en pruebas automatizadas como *token* simulado. |
| *Spike* | Investigación acotada en el tiempo para reducir incertidumbre técnica antes de comprometer un diseño. |
| SVA | Prestador de Servicios de Valor Añadido dentro de la IOFE (por ejemplo, sellado de tiempo). |
| TSA | *Time Stamping Authority* (RFC 3161): emite sellos de tiempo confiables. |
| Token | Dispositivo criptográfico (aquí, el chip del DNIe) que guarda claves no exportables. |
| WYSIWYS | *What You See Is What You Sign*: principio por el cual el usuario debe ver exactamente el contenido que firma. |
| XAdES | *XML Advanced Electronic Signatures* (ETSI EN 319 132). |
