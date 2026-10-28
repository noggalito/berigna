# Arquitectura general

| Campo | Valor |
|---|---|
| Documento | BRG-ARQ-001 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Principios

1. Núcleo independiente de la interfaz. `berigna.core` no importa GTK. Esto facilita las pruebas automatizadas y la evaluación para la acreditación, y deja preparada la CLI y el invocador web de la hoja de ruta, aunque la v1 solo tiene GUI.
2. La clave nunca sale del chip. El núcleo solo obtiene del *token* el resultado de la operación de firma.
3. Adaptadores por formato. PAdES, CAdES y XAdES implementan una misma interfaz `Signer` y una misma interfaz `Validator`, de modo que cambiar una biblioteca no afecta al resto del sistema.
4. Mínimo de piezas propias en criptografía. Se usan bibliotecas maduras (pyHanko, cryptography, asn1crypto, python-pkcs11). Solo se escribe código propio para la integración y las reglas del dominio peruano.
5. Explícito ante lo ambiguo. Toda decisión con impacto legal (nivel, certificado, advertencias) se muestra al usuario.
6. Bilingüe desde el diseño (ADR-0011, ADR-0015). El núcleo devuelve resultados con códigos, no frases. La traducción a es_PE o quechua se hace en la capa de presentación y en el generador de informes.

## 2. Contexto (C4, nivel 1)

```mermaid
flowchart TB
  user([Titular del DNIe / receptor])
  subgraph host[Equipo Debian del usuario]
    berigna[berigna<br/>aplicación GTK4]
    nautilus[Nautilus]
    pcscd[pcscd + libccid]
    p11[Módulo PKCS#11<br/>OpenSC: otros tokens / DNIe v1]
  end
  reader[Lector USB CCID]
  dnie[(Chip DNIe)]
  tsa[TSA acreditada]
  reniec[OCSP / CRL / AIA<br/>RENIEC]

  user --> berigna
  user --> nautilus
  nautilus -- rutas de archivo vía D-Bus --> berigna
  berigna -- PKCS#11 --> p11 --> pcscd
  berigna -- "PC/SC: APDU (DNIe v2, ADR-0012)" --> pcscd
  pcscd --> reader --> dnie
  berigna -- RFC 3161 / HTTPS --> tsa
  berigna -- RFC 6960 / HTTP --> reniec
```

## 3. Contenedores y módulos (C4, nivel 2-3)

```mermaid
flowchart TB
  subgraph ui[berigna.ui: GTK4 + libadwaita]
    win[MainWindow]
    sign_view[SignView<br/>previsualización + opciones]
    verify_view[VerifyView]
    batch_view[BatchView]
    prefs[PreferencesDialog]
    diag[DiagnosticsDialog]
    pin[PinDialog]
  end

  subgraph core[berigna.core: sin dependencias de GTK]
    svc_sign[SigningService]
    svc_verify[ValidationService]
    svc_batch[BatchRunner]
    token[token<br/>TokenManager, TokenSession]
    subgraph fmt[formats]
      pades[pades: PadesSigner / PadesValidator]
      cades[cades: CadesSigner / CadesValidator]
      xades[xades: XadesSigner / XadesValidator]
    end
    trust[trust: TrustStore]
    net[net: TsaClient, RevocationClient, HttpFetcher]
    appearance[appearance: renderizado de la firma visible]
    settings[config: Settings, ver ADR]
    history[history: HistoryStore]
    report[report: informes PDF/JSON]
    i18n[i18n: gettext es_PE / quz]
  end

  subgraph ext[berigna-nautilus]
    menu[MenuProvider]
  end

  menu -- "D-Bus: org.gtk.Application.Open" --> win
  win --> sign_view & verify_view & batch_view
  sign_view --> svc_sign
  verify_view --> svc_verify
  batch_view --> svc_batch --> svc_sign
  svc_sign --> token & pades & cades & xades & trust & net & appearance & history
  svc_verify --> pades & cades & xades & trust & net & report
  pades & cades & xades --> net
  report & appearance --> i18n
```

### 3.1 Responsabilidades

| Módulo | Responsabilidad | Bibliotecas (estado al 2026-10-27) |
|---|---|---|
| `core.token` | Detección de lectores y tarjetas, y selección del *backend* según el ATR. Dos *backends* con la misma interfaz `TokenSigner`: `dnie_v2`, driver APDU para el DNIe v2 (*applet* PKI, lectura de certificados, VERIFY, MSE:SET y PSO:CDS, con lista blanca de instrucciones), y `pkcs11`, el genérico (*slots*, login y logout, `C_Sign`) | pyscard (ADR-0012), implementado para el DNIe v2, con monitor en caliente; python-pkcs11 (ADR-0003), aplazado a la versión 1.1 |
| `core.formats.pades` | Firma y validación PAdES, DSS/VRI, sellos de documento, DocMDP. Firma mediante un `Signer` personalizado de pyHanko que delega en `TokenSigner` | pyHanko 0.25.1 (ADR-0004, ADR-0013); implementada la firma B-B, B-T, B-LT y B-LTA |
| `core.formats.cades` | Firma y validación CMS/CAdES separada y envuelta | pyHanko (API CMS genérica), asn1crypto (ADR-0008) |
| `core.formats.xades` | Firma y validación XAdES | Según SPK-03 (ADR-0008) |
| `core.trust` | Almacén de confianza de la IOFE incluido (anclas como recurso del paquete con manifiesto de huellas), anclas añadidas por el usuario y TSL de INDECOPI (`tsl`, ADR-0014) | cryptography, lxml, signxml; implementado |
| `core.net` | Clientes HTTP para TSA, OCSP, CRL y AIA, con caché, tiempos de espera y proxy | requests. Implementados `fetchers` (OCSP y CRL para validación previa, firma B-LT y verificación) y `tsa` (cliente RFC 3161 sobre el de pyHanko). Caché y proxy, pendientes |
| `core.appearance` | Composición del sello visible a partir de una plantilla de texto y una imagen | pyHanko stamp + Pillow |
| `core.signing` | Orquestación: comprobar que el archivo no cambió, validar el certificado antes del PIN, firmar y escribir de forma atómica | Implementado para PDF (B-B) |
| `core.validation` | Validación previa del firmante (`preflight`, RF-006) y verificación de firmas PDF con indicaciones ETSI (`pdf`, RF-050, RF-053, RF-055) | pyhanko-certvalidator 0.26.3 y la validación AdES de pyHanko 0.25.1; `preflight` implementado; `pdf` con sellos de tiempo y validación en el pasado |
| `core.report` | Explicaciones en lenguaje llano de cada indicación y subindicación ETSI y de cada `ERR-xxx` (`messages`, `explanations`); informe de verificación en JSON con explicaciones en ambos idiomas (`json_report`) y en PDF en es_PE o en quechua (`pdf_report`) | gettext, ReportLab; implementado |
| `core.i18n` | Idiomas es_PE y quechua sureño, elección según la configuración del usuario con es_PE de respaldo (ADR-0015) y carga de los catálogos; el quechua cae en es_PE, nunca en el texto fuente inglés | gettext de la biblioteca estándar; implementado |
| `core.history` | Historial local en SQLite | sqlite3 (biblioteca estándar) |
| `core.config` | Acceso tipado a la configuración (GSettings vía una interfaz, para no acoplar el núcleo a GTK) | — |
| `ui` | Vistas, diálogos, previsualización de PDF y manejo de hilos | PyGObject, GTK4, libadwaita, Poppler-GLib o pypdfium2 |
| `berigna-nautilus` | Entradas del menú contextual; solo lanza berigna con las rutas | nautilus-python |

### 3.2 Límites deliberados del driver del DNIe v2

Decisiones de implementación de `core.token.dnie_v2` (ADR-0012), documentadas para la auditoría:

| Decisión | Motivo |
|---|---|
| La lista blanca valida la forma exacta de cada comando (AID, archivos, referencia de PIN, plantilla de MSE, `DigestInfo` SHA-2), no solo la instrucción | AM-19: ninguna ruta de código puede enviar otra cosa al chip |
| `signing_certificate()` solo comprueba el uso de clave (no repudio); la vigencia, la cadena y la revocación las valida la capa de validación (RF-006) | Separación de responsabilidades |
| PSO:CDS se envía sin `Le` | Comportamiento verificado en el DNIe real (SPK-01 §8.6 y HIL del 2026-10-27) |
| Ante un fallo transitorio de PC/SC (`SCARD_E_NOT_TRANSACTED`), SELECT y READ BINARY se reintentan hasta dos veces (50 y 150 ms). VERIFY, MSE:SET y PSO:CDS no se reintentan nunca y la sesión se cierra | Medido: 1 de cada 30 sesiones encadenadas fallaba tras el apagado de la anterior; con la política, 0 de 60. Reenviar un VERIFY podría gastar un intento del PIN (P-06) |
| Límite de longitud del PIN: 255 bytes | Límite de una APDU; la política real la aplica la tarjeta |
| `Pin.buffer()` devuelve el búfer vivo, y su único consumidor es `verify_pin`, que lo borra | P-04; la confianza se limita a un solo punto del código |
| El monitor (`core.token.monitor`) consulta `SCardGetStatusChange` con tiempo de espera 0 y duerme entre sondeos con un `threading.Event` | Decisión deliberada: `stop()` responde de inmediato, sin esperar a que pcscd devuelva una llamada bloqueante ni recurrir a `SCardCancel`; el coste de CPU de dos sondeos por segundo es despreciable |
| Los nombres de lector se normalizan a `str` aunque pyscard los devuelva como `bytes` | El contrato de `ReaderState` no depende de la versión de pyscard |
| `sign_pdf_file` comprueba que el PDF se puede leer antes de validar el certificado y pedir el PIN | Un archivo dañado no le cuesta al usuario teclear el PIN |
| `verify_pdf` elige el proceso de ETSI según la firma: el básico (`ades_basic_validation`) si no tiene sello de tiempo y el de material de validación a largo plazo (`ades_lta_validation`) si lo tiene. La integridad del PDF (cobertura, diferencias) se calcula por separado | `ades_lta_validation` exige un sello de tiempo y da INDETERMINATE a toda firma B-B; y `ades_basic_validation` de pyHanko 0.25.1 falla si se le pide el estado propio de PDF |
| Si pyHanko devuelve la subindicación genérica `CERTIFICATE_CHAIN_GENERAL_FAILURE` en el proceso básico, la cadena se valida otra vez por separado y la subindicación se precisa según el error: falta de datos de revocación → `TRY_LATER`, certificado vencido en la cadena → `OUT_OF_BOUNDS_NO_POE`, aún no vigente → `NOT_YET_VALID`. Si esta vez pasa, el primer fallo fue transitorio → `TRY_LATER` | pyHanko 0.25.1 agrupa esas causas, que ETSI EN 319 102-1 (§5.2.6) distingue y DSS informa por separado. Cada una lleva una explicación distinta para el usuario (RF-053) |
| La política de algoritmos (resúmenes MD2, MD5 y SHA-1 prohibidos; RSA de al menos 2048 bits) está escrita en `core.validation.algorithms` y se aplica a cadenas, firmas y sellos en la validación previa y en la verificación. La validación previa comprueba además la clave del propio firmante | ACR-18. Los valores por defecto de pyhanko-certvalidator podrían cambiar con una actualización; y su política solo juzga las claves que firman a otros certificados, no la del firmante |
| Si falta un catálogo de traducción, se devuelve el texto fuente; las explicaciones lo detectan y quedan vacías, y los informes se generan igual | Una instalación incompleta no impide verificar ni exportar, y no se mezclan idiomas |
| Cada sello (de firma y de documento) se informa con su propia indicación (§5.4). Si pyHanko no devuelve el estado del sello de la firma, porque el proceso se detuvo antes, el sello se valida aparte | RF-053: un sello inválido se muestra aunque la firma sea válida, y al revés |
| Al verificar, la indicación ETSI y las modificaciones posteriores se informan por separado; una cobertura que no abarca una revisión completa es TOTAL-FAILED/FORMAT_FAILURE | La firma puede ser íntegra aunque el documento cambiara después (RF-055); un rango de bytes parcial es la huella de un ataque de envoltura (AM-05) |
| En línea (validación previa, firma B-LT y verificación), nunca se descarga la CRL de un certificado final (solo OCSP); las CRL se descargan para las CA, con descarga propia: se pide al primer espejo y el siguiente solo entra si el anterior no responde en 2 s o falla; gana la primera CRL que llega. Tiempo de conexión de 20 s, separado del de lectura. Cada consulta fallida se reintenta una vez tras 0,5 s, salvo un OCSP cuya conexión agotó los 20 s (`core.net.fetchers`) | La CRL de la CA emisora del DNIe pesa ~109 MB (RF-063). La red de RENIEC descarta intentos de conexión de forma intermitente (conexiones a `crl2` de 12,6 y 15,25 s, OCSP sin respuesta durante más de 20 s; R-17). pyhanko-certvalidator 0.26.3 fallaba si cualquier espejo fallaba y guardaba en caché las descargas fallidas |
| Un nivel por encima de B-B exige, antes de pedir el PIN, revocación comprobada y una TSA que acabe de emitir un sello de prueba | Ninguno de esos fallos le cuesta al usuario teclear el PIN (RF-006) |
| B-LT y B-LTA se añaden después de que la tarjeta firmó, como actualizaciones incrementales. Si falla un servicio en ese punto, se conserva la firma y el resultado indica el nivel alcanzado y el motivo | No se pierde una firma ya hecha; la interfaz debe avisar del nivel real. Un fallo de la TSA al sellar la firma misma sí anula la operación (no se escribe nada) |
| La comprobación de la TSA tiene un plazo total (30 s por defecto) y su petición HTTP es síncrona, en un hilo *daemon* propio | El tiempo de espera de `requests` es por operación: con IPv6 roto, urllib3 espera ese tiempo por cada dirección IPv6 de la TSA (visto con freetsa.org). El cliente de pyHanko usa `asyncio.to_thread`, cuyos hilos no son *daemon* y bloquearían el cierre de la aplicación |
| La interfaz traduce sus vistas (GtkBuilder) en Python con `core.i18n`, en lugar de dejarlo a GTK (`berigna.ui.i18n.translate_view`) | GTK traduce con el gettext de la biblioteca de C, que ignora `LANGUAGE` con la configuración regional C o C.UTF-8 y mostraría el texto fuente en inglés (comprobado el 2026-10-28). Así la interfaz no depende de las configuraciones regionales generadas, aplica las mismas reglas de respaldo que los informes (quechua pendiente → es_PE) y puede cambiar de idioma sin reiniciar |
| Abrir un documento lo lee una vez y calcula su SHA-256 (`core.documents.inspect_document`), en un hilo de trabajo | La firma comprueba después que el archivo sigue siendo el mostrado (RF-018); un PDF grande no bloquea la interfaz |
| Al validar en el momento actual, la tolerancia de tiempo para los datos de revocación es de 5 minutos (`CURRENT_TIME_TOLERANCE`); en una fecha pasada, 1 s | El momento se fija antes de consultar los servicios, y su respuesta lleva la hora en que se produjo: con 1 s, una respuesta de RENIEC que tardó 2,6 s era "demasiado reciente" y la firma salía INDETERMINATE (2026-10-28). Los servicios pueden tardar hasta un minuto (R-17) |
| La verificación corre en un hilo de trabajo y su resultado se descarta si el usuario ya abrió otro documento (`ui.verification`) | Puede tardar segundos por la red; la interfaz no se bloquea y nunca muestra el resultado de un documento que ya no está a la vista |

## 4. Interfaces clave del núcleo

Implementadas (Fases 1 y 2):

```python
class TokenSigner(Protocol):                      # core.token.base
    def signing_certificate(self) -> x509.Certificate: ...
    def verify_pin(self, pin: Pin) -> None: ...   # un solo intento; borra el PIN
    def sign_digest(self, digest: bytes, algorithm: HashAlgorithmName = "sha256") -> bytes: ...
    def close(self) -> None: ...                  # también como gestor de contexto

def check_signer(certificate, store, *, moment=None, online=True,
                 ocsp_responses=(), crls=(), timeout=10.0) -> SignerCheck   # core.validation
# SignerCheck: revocation_checked, chain, moment y revocation_note (OFFLINE o UNAVAILABLE
# cuando no se pudo comprobar la revocación y solo cabe B-B)

def verify_pdf(data, store, *, moment=None, online=True, ocsp_responses=(), crls=(),
               timeout=10.0) -> PdfVerification                          # core.validation
# PdfVerification: signatures (PdfSignatureReport: indicación y subindicación ETSI, firmante,
# cobertura, modificaciones posteriores, longitud de la revisión firmada y sello de tiempo de
# la firma) y document_timestamps (TimestampReport de cada sello de documento)

def sign_pdf_file(source, output, *, expected_sha256, token, store, ask_pin, options=None,
                  level=SignatureLevel.B_B, timestamper=None, online=True,
                  ocsp_responses=(), crls=()) -> SignResult                     # core.signing
# SignResult.level es el nivel alcanzado; level_note explica por qué es inferior al pedido

def sign_pdf_pades(pdf, token, chain, options=None, *, level=SignatureLevel.B_B,
                   timestamper=None, validation_context=None) -> PadesResult  # core.formats.pades

def load_tsl(data, *, moment=None, signer_crl=None, minimum_sequence=None) -> TrustedList  # core.trust.tsl
def fetch_tsl(*, url=TSL_URL, timeout=30.0) -> TrustedList
def extend_store(store, trusted_list) -> TrustStore

def report_data(verification, *, file_name, file_sha256, store) -> dict           # core.report.json_report
def pdf_report(verification, *, file_name, file_sha256, store,
               language=Language.ES_PE) -> bytes                                  # core.report.pdf_report
def http_timestamper(TsaSettings(url, timeout, username, password)) -> TimeStamper  # core.net.tsa
def probe(timestamper, md_algorithm="sha256", deadline=30.0) -> None              # core.net.tsa
```

Diseño previsto para las fases siguientes (no es código final):


```python
# Pseudocódigo de diseño, no es código final.

class SignatureLevel(Enum):
    B_B = "B-B"; B_T = "B-T"; B_LT = "B-LT"; B_LTA = "B-LTA"

class SignatureFormat(Enum):
    PADES = auto(); CADES_DETACHED = auto(); CADES_ENVELOPING = auto()
    XADES_ENVELOPED = auto(); XADES_ENVELOPING = auto(); XADES_DETACHED = auto()

@dataclass(frozen=True)
class SignRequest:
    source: Path
    source_digest: bytes          # SHA-256 de los bytes previsualizados (RF-018)
    output: Path
    format: SignatureFormat
    level: SignatureLevel
    metadata: SignMetadata         # motivo, ubicación, contacto
    appearance: Appearance | None  # solo PAdES visible
    certify: DocMdpLevel | None

class Signer(Protocol):
    def sign(self, req: SignRequest, key: TokenSigner, ctx: SignContext) -> SignResult: ...

class Validator(Protocol):
    def validate(self, target: Path, ctx: ValidationContext) -> list[SignatureReport]: ...

class TokenSigner(Protocol):
    certificate: x509.Certificate
    chain: list[x509.Certificate]
    def sign_digest(self, digest: bytes, algorithm: str) -> bytes: ...
```

## 5. Modelo de concurrencia

- La interfaz se ejecuta en el bucle principal de GLib.
- Las operaciones del núcleo se ejecutan en un único hilo de trabajo dedicado al *token* (las llamadas al *token*, sea PKCS#11 o APDU sobre una única conexión PC/SC, se serializan). La red y la validación pueden usar un pool de hilos aparte.
- `check_signer` (y por tanto `sign_pdf_file`) crea su propio bucle de asyncio para pyhanko-certvalidator: debe llamarse desde un hilo de trabajo, nunca desde dentro de un bucle de asyncio en marcha.
- La comunicación hacia la interfaz se hace con `GLib.idle_add` o con `Gio.Task`. La cancelación usa `Gio.Cancellable`, que se traduce a un token de cancelación del núcleo.
- La detección de lectores y tarjetas (`core.token.monitor`) sondea cada 0,5 s con `SCardGetStatusChange` en un hilo propio, sin conectarse a la tarjeta, de modo que no interfiere con una sesión de firma exclusiva. Solo avisa cuando cambia el estado (sin servicio PC/SC, sin lector, sin tarjeta, tarjeta no compatible con su ATR, DNIe listo), y la interfaz debe pasar el aviso al bucle principal con `GLib.idle_add`.

## 6. Proceso y empaquetado

- Un solo proceso `berigna`, con `Adw.Application` y un `application-id` único: `pe.berigna.Berigna` (provisional, depende de DP-05; debe ser un dominio controlado por el titular).
- La extensión de Nautilus es un módulo Python aparte, instalado en el directorio de extensiones de nautilus-python, en un paquete binario propio (`berigna-nautilus`).
- Estructura de paquetes Debian: `berigna` (aplicación), `berigna-nautilus` (extensión), `python3-berigna-core` (opcional, si se separa el núcleo).

## 7. Decisiones de arquitectura

Ver [adr/README.md](adr/README.md).

## 8. Puntos abiertos

- Driver de OpenSC para el DNIe v2 (línea paralela de ADR-0012): repositorio, mantenedor y plan de envío *upstream*.

- Previsualización de PDF: Poppler-GLib (vía GObject Introspection, ya integrada en Debian) frente a pypdfium2 (mejor fidelidad, pero no empaquetada en Debian). Se decide en la Fase 3 con un ADR.
- Si el núcleo se publica como una biblioteca separada (`python3-berigna-core`) o solo como un paquete interno.
