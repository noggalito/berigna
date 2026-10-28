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
6. Bilingüe desde el diseño (ADR-0011). El núcleo devuelve resultados con códigos, no frases. La traducción a es_PE o en_US se hace en la capa de presentación y en el generador de informes.

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
    i18n[i18n: gettext es_PE / en_US]
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
| `core.token` | Detección de lectores y tarjetas, y selección del *backend* según el ATR. Dos *backends* con la misma interfaz `TokenSigner`: `dnie_v2`, driver APDU para el DNIe v2 (*applet* PKI, lectura de certificados, VERIFY, MSE:SET y PSO:CDS, con lista blanca de instrucciones), y `pkcs11`, el genérico (*slots*, login y logout, `C_Sign`) | pyscard (ADR-0012), implementado para el DNIe v2; python-pkcs11 (ADR-0003), pendiente |
| `core.formats.pades` | Firma y validación PAdES, DSS/VRI, sellos de documento, DocMDP. Firma mediante un `Signer` personalizado de pyHanko que delega en `TokenSigner` | pyHanko 0.25.1 (ADR-0004, ADR-0013); implementada la firma B-B |
| `core.formats.cades` | Firma y validación CMS/CAdES separada y envuelta | pyHanko (API CMS genérica), asn1crypto (ADR-0008) |
| `core.formats.xades` | Firma y validación XAdES | Según SPK-03 (ADR-0008) |
| `core.trust` | Almacén de confianza de la IOFE incluido (anclas como recurso del paquete con manifiesto de huellas) y anclas añadidas por el usuario | cryptography; implementado |
| `core.net` | Clientes HTTP para TSA, OCSP, CRL y AIA, con caché, tiempos de espera y proxy | requests. Hoy OCSP y CRL los obtiene pyhanko-certvalidator con sus *fetchers* de `requests` (10 s de tiempo de espera); el módulo propio llega con la TSA (Fase 2) |
| `core.appearance` | Composición del sello visible a partir de una plantilla de texto y una imagen | pyHanko stamp + Pillow |
| `core.signing` | Orquestación: comprobar que el archivo no cambió, validar el certificado antes del PIN, firmar y escribir de forma atómica | Implementado para PDF (B-B) |
| `core.validation` | Validación previa del firmante (`preflight`, RF-006) y, en la Fase 2, validación de firmas con normalización a indicaciones ETSI | pyhanko-certvalidator 0.26.3; `preflight` implementado |
| `core.report` | Informe de verificación en JSON (códigos y explicaciones en ambos idiomas) y en PDF (en es_PE o en_US) | ReportLab o pyHanko |
| `core.i18n` | Inicialización de gettext, catálogo de explicaciones por código (ETSI y `ERR-xxx`), formato de fechas según la configuración regional y selección explícita del idioma de los documentos generados (informe, sello visible) | gettext, babel o `locale` de la biblioteca estándar |
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

## 4. Interfaces clave del núcleo

Implementadas (Fase 1):

```python
class TokenSigner(Protocol):                      # core.token.base
    def signing_certificate(self) -> x509.Certificate: ...
    def verify_pin(self, pin: Pin) -> None: ...   # un solo intento; borra el PIN
    def sign_digest(self, digest: bytes, algorithm: HashAlgorithmName = "sha256") -> bytes: ...
    def close(self) -> None: ...                  # también como gestor de contexto

def check_signer(certificate, store, *, moment=None, online=True,
                 ocsp_responses=(), crls=(), timeout=10.0) -> SignerCheck   # core.validation

def sign_pdf_file(source, output, *, expected_sha256, token, store, ask_pin,
                  options=None, online=True, ocsp_responses=(), crls=()) -> SignResult  # core.signing
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
- La comunicación hacia la interfaz se hace con `GLib.idle_add` o con `Gio.Task`. La cancelación usa `Gio.Cancellable`, que se traduce a un token de cancelación del núcleo.
- La detección de lectores y tarjetas se hace con un sondeo de baja frecuencia (1 s) o, si el módulo lo soporta, con `C_WaitForSlotEvent` en un hilo propio.

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
