# Configuración y datos

| Campo | Valor |
|---|---|
| Documento | BRG-ARQ-003 |
| Versión | 0.4.0 |
| Estado | Borrador |
| Fecha | 2026-10-29 |
| Responsable | noggalito |

## 1. Ubicaciones (XDG)

| Dato | Ruta | Formato | Sensible |
|---|---|---|---|
| Preferencias | GSettings, esquema `com.noggalito.Berigna` (en dconf) | GVariant | No |
| Almacén de confianza (incluido en el paquete) | Recurso del paquete Python: `berigna/core/trust/anchors/` (en el código fuente, `src/berigna/core/trust/anchors/`) | PEM y `manifest.json` con huellas SHA-256; el paquete `.deb` firmado protege su integridad | No |
| Anclas añadidas por el usuario | `$XDG_DATA_HOME/berigna/trust/` (prevista: `TrustStore.with_user_anchors` existe, la interfaz para añadirlas no) | PEM | No |
| TSL de INDECOPI | `$XDG_DATA_HOME/berigna/tsl/` (`core.trust.cache`) | XML firmado y número de secuencia aceptado | No |
| Imágenes de la firma visible | `$XDG_DATA_HOME/berigna/apariencia/` (carpeta 0700): `rubrica.png` y `logotipo.png` (ADR-0018 §6) | PNG sin metadatos, archivos 0600 | Sí (la rúbrica) |
| Perfiles de apariencia con nombre | Previstos (RF-081), en la misma carpeta | JSON | No |
| Historial | `$XDG_DATA_HOME/berigna/history.sqlite3` | SQLite | Sí (nombres de archivo) |
| Caché de OCSP, CRL y AIA | `$XDG_CACHE_HOME/berigna/revocation/` (prevista; hoy la caché vive en memoria durante cada operación) | DER | No |
| Registro técnico | `$XDG_STATE_HOME/berigna/logs/berigna.log` (carpeta 0700) | Texto, rotativo (5 × 1 MB); INFO, o DEBUG con `BERIGNA_DEBUG=1` (`core.logs`) | Bajo: nunca el PIN ni el contenido de los documentos; todo número de cinco o más cifras (DNI, RUC) se enmascara a sus cuatro últimas, también en las trazas |
| Registro de fallos | `pending-failure.txt` y `faulthandler.txt`, en la carpeta del registro técnico (0600) | Texto: trazas de las excepciones no capturadas y de los fallos de código nativo, cada una con su fecha (UTC) y la versión de berigna (`core.crashes`, R-DES-11); como máximo 64 KiB, se descarta lo más antiguo | Bajo: las mismas reglas que el registro técnico, y la carpeta personal escrita como `~`. El informe pendiente se ofrece en el siguiente arranque y se borra cuando la persona responde; nunca se envía solo |
| Credenciales de la TSA (si hay) | Llavero del sistema (libsecret, Secret Service) | — | Sí |

Los permisos de los datos propios de berigna son `0600` y los de sus directorios `0700`. Los archivos firmados y los informes exportados son documentos del usuario: se crean con los permisos de cualquier archivo nuevo según su máscara (`core.files.write_atomically`).

## 2. Esquema de GSettings

Implementado en `data/com.noggalito.Berigna.gschema.xml` (Fase 3, incremento 1). Desde el incremento 4 la interfaz usa además `default-level`, `digest-algorithm`, `output-suffix`, `output-directory`, `tsa-url`, `network-timeout`, `proxy-mode`, `proxy-url`, `signature-reason` y `signature-location`, y las Preferencias muestran casi todas. `tsa-auth` (usuario y contraseña en libsecret, o certificado de cliente) queda para cuando haya una TSA contratada que lo exija (DP-02).

Proxy (RF-064): el valor se aplica a las variables de entorno estándar del proceso (`https_proxy`, `no_proxy`), que `requests` lee en cada petición, también dentro de pyhanko-certvalidator (`core.net.proxy`). Con `system`, la interfaz pregunta a GIO por el proxy del escritorio.

| Clave | Tipo | Defecto | Descripción |
|---|---|---|---|
| `default-level` | enum | `'B-LT'` (DP-04) | Nivel preseleccionado |
| `pdf-format` | enum | `'pades'` | Formato para PDF |
| `xml-format` | enum | `'xades-enveloped'` | Formato para XML |
| `other-format` | enum | `'cades-detached'` | Formato para el resto de archivos |
| `output-suffix` | s | `'-firmado'` | Sufijo del archivo de salida |
| `output-directory` | s | `''` | Vacío: la misma carpeta que el original |
| `digest-algorithm` | enum | `'sha256'` | — |
| `tsa-url` | s | `''` (DP-02) | URL de la TSA |
| `tsa-auth` | enum | `'none'` | none / basic / client-cert |
| `network-timeout` | u | `10` | Segundos de espera de la respuesta (lectura). La conexión espera al menos 20 s, para cubrir los reenvíos de SYN de la red de RENIEC (R-17, `core.net.fetchers`) |
| `proxy-mode` | enum | `'system'` | system / manual / none |
| `proxy-url` | s | `''` | — |
| `visible-signature` | b | `false` | Activar la firma visible por defecto; con `false`, la lista de apariencias muestra "No visible" |
| `appearance-kind` | enum | `'text'` | text / rubric / logo / qr: apariencia de la firma visible (ADR-0018) |
| `appearance-language` | enum | `'es_PE'` | es_PE / quz_PE: idioma de los textos fijos y de la fecha del sello (RF-092) |
| `appearance-dni` | enum | `'last-four'` | last-four / full / hidden: cómo muestran el DNI el sello y su QR (decisión del 2026-10-28). El certificado incrustado lleva siempre el DNI completo |
| `appearance-profile` | s | `''` | Perfil por defecto (perfiles con nombre, RF-081: pendiente) |
| `signature-reason-kind` | enum | `'none'` | none / authorship / agreement / endorsement / approval / on-behalf / other: último motivo elegido de la lista (`core.reasons`) |
| `signature-reason` | s | `''` | Texto del último motivo "Otro" |
| `signature-location` | s | `''` | Última ubicación usada |
| `recent-locations` | as | `[]` | Hasta cinco ubicaciones usadas, la más reciente primero; se ofrecen en la lista |
| `history-enabled` | b | `true` | — |
| `history-full-path` | b | `false` | Guardar la ruta completa del archivo en el historial; por defecto solo el nombre (AM-12) |
| `pkcs11-module` | s | `''` | Vacío: detección automática. Solo se usa con el *backend* PKCS#11 (ADR-0012) |
| `token-backend` | enum | `'auto'` | auto (según el ATR) / dnie-v2 / pkcs11 |
| `crl-fallback` | b | `false` | Permite descargar CRL como respaldo de OCSP al verificar (la de la CA del DNIe pesa unos 109 MB) |
| `ui-language` | enum | `'system'` | system / es_PE / quz_PE; se aplica al momento (ADR-0011, ADR-0015). en_US se añade en la 1.1 |
| `report-language` | enum | `'ui'` | ui / es_PE / quz_PE: idioma del informe PDF exportado |

Cuando existan los perfiles de apariencia con nombre (RF-081), su JSON incluirá el campo `"language": "es_PE" | "quz_PE"`, que define el idioma de los textos fijos y del formato de fecha del sello visible (RF-092); hoy lo define `appearance-language`.

Despliegue en organizaciones: un administrador puede definir valores por defecto y bloquear claves mediante archivos en `/etc/dconf/db/local.d/` y `locks/`. Esto se documentará en el manual de administración.

## 3. Almacén de confianza

- Contenido: las raíces e intermedias de la IOFE necesarias para los certificados del DNIe y para las TSA acreditadas. La lista exacta sale de SPK-04 y de SPK-02.
- Cadena del DNIe v2, identificada en SPK-01 y SPK-02. Huellas contrastadas el 2026-10-28 con los certificados del repositorio oficial de RENIEC (`https://pki.reniec.gob.pe/repositorio/`, indicado por RENIEC en su respuesta a CE-07); la página es HTTPS, pero los enlaces de descarga son HTTP, y RENIEC no publica las huellas aparte:

  | Certificado | SHA-256 |
  |---|---|
  | ECERNEP PERU CA ROOT 3 (raíz) | `9650 8217 C36F 3BBC 556E 2E07 D7AB 50C4 0DA8 027C 3882 3581 3322 E41B 87A5 68BE` |
  | ECEP-RENIEC | `9152 0E1F 381A 4640 2B94 90C0 6749 B2D8 1DDA D4B5 3E7F 252A 1DD7 9B55 DFCB 340B` |
  | ECEP-RENIEC CA Class 2 II | `EC94 327A 45C4 5A92 8104 D389 B352 5769 18B8 C072 3272 04E1 5E1F 8854 7D86 0A42` |
  | ECEP-RENIEC CA Class 3 (de ROOT 3, 2024-2032; añadida el 2026-10-28: el repositorio la publica y la TSL de INDECOPI no la incluye) | `1901 5493 A1CC 0041 1643 FCE4 F48D 8D17 CBA8 D50F 685E 9174 9103 E601 FA61 A9EC` |

- Cadena ROOT 5 (personas jurídicas), obtenida el 2026-10-27. La raíz se descargó por HTTPS desde `cdn.www.gob.pe`; las intermedias, por HTTP desde los dos espejos de RENIEC, que dieron archivos idénticos. La cadena se verificó con un certificado real de SUNARP:

  | Certificado | SHA-256 |
  |---|---|
  | ECERNEP PERU CA ROOT 5 (raíz, vigente hasta 2047) | `E33D 6A09 352F 98BA 5CC9 E358 D44F 3ED7 37E8 C73F 29E5 6656 F96A A05A 9D34 DA60` |
  | ECEP-RENIEC CA ROOT 5 | `E827 B4CF 0DE3 24C8 E92A B20D B973 A070 4883 AE98 2DB1 A108 C834 48EA 463D C3AC` |
  | ECEP-RENIEC CA Class 3 | `483A 02FB A5A8 2D23 D8C3 AC32 4157 DF39 2229 C0DF 750B 77F2 5096 8807 875D DEC1` |

- Implementación (`berigna.core.trust`): las anclas van como recurso del paquete en `src/berigna/core/trust/anchors/`, con `manifest.json` (huella, rol, jerarquía, origen y forma de verificación). Al cargar el almacén se comprueba cada huella contra el manifiesto. Una diferencia, un archivo que sobra o falta, o un rol que no corresponde al certificado invalidan el almacén entero (ERR-201).

- Fuente preferente: la TSL de INDECOPI (ETSI TS 102 231, firmada por INDECOPI; guía v4.0 §3.3 y ACR-24). URL pendiente (Q8).
- Manifiesto: `trust/manifest.json`, con la huella SHA-256, el origen (URL oficial), la fecha de obtención y el propósito (firma o TSA) de cada certificado.
- Integridad: el manifiesto se publica dentro del paquete `.deb` firmado. La aplicación comprueba al arrancar que las huellas coinciden con el manifiesto.
- Actualización: el almacén base, con nuevas versiones del paquete (RF-061). Las CA de la TSL de INDECOPI se añaden en tiempo de ejecución: la lista se comprueba al arrancar si la guardada tiene más de un día, y desde Preferencias → Confianza → "Actualizar ahora" (ADR-0014).
- Caché de la TSL: `$XDG_DATA_HOME/berigna/tsl/` (normalmente `~/.local/share/berigna/tsl/`), con la lista tal como se descargó (`tsl-pe.xml`) y `estado.json` (número de secuencia aceptado y fecha de descarga). La lista guardada se vuelve a verificar cada vez que se lee; una lista con un número de secuencia menor que el aceptado se rechaza (vuelta atrás). La CRL del firmante no se guarda: la revocación se comprobó al aceptar la lista (`core.trust.cache`).

## 4. Historial (SQLite)

```sql
CREATE TABLE operation (
  id            INTEGER PRIMARY KEY,
  ts_utc        TEXT    NOT NULL,           -- ISO 8601
  kind          TEXT    NOT NULL,           -- sign | verify | batch
  file_name     TEXT    NOT NULL,           -- nombre del archivo; la ruta completa solo si history-full-path = true
  file_sha256   TEXT    NOT NULL,           -- del archivo original (o del verificado)
  signed_name   TEXT,                       -- nombre del archivo firmado
  signed_sha256 TEXT,                       -- su SHA-256, para encontrar la fila de un archivo
  format        TEXT,
  level         TEXT,
  signer_cn     TEXT,                       -- nombre del firmante
  signer_serial TEXT,                       -- número de serie del certificado
  result        TEXT    NOT NULL,           -- ok | error | TOTAL-PASSED | ...
  detail        TEXT
);
```

No se guarda el número de DNI completo ni el contenido de los documentos. Implementado en la Fase 3, incremento 6 (`core.history`): `kind` es `sign`, `batch` (una fila por documento del lote) o `verify`; `result` es `ok` o `error` (con el `ERR-xxx` en `detail`) en las firmas, y la peor indicación ETSI en las verificaciones (con "válidas/total" en `detail`). El archivo se crea con permisos 0600 y su carpeta con 0700 (CS-11); "Borrar el historial" borra las filas y compacta el archivo (`VACUUM`). Se exporta a CSV desde la página Historial.

## 5. Formato del informe JSON de verificación (borrador)

```json
{
  "berigna_version": "1.0.0",
  "validated_at": "2026-10-27T15:04:05Z",
  "report_language": "es_PE",
  "file": {"name": "contrato-firmado.pdf", "sha256": "…"},
  "trust_store": {"manifest_sha256": "…", "user_anchors": false},
  "signatures": [
    {
      "id": "Signature1",
      "format": "PAdES",
      "level": "B-LT",
      "signer": {"name": "…", "dni_masked": "****5678", "cert_serial": "…", "issuer": "…"},
      "signing_time": {"claimed": "…", "timestamp": "…", "tsa": "…"},
      "indication": "TOTAL-PASSED",
      "sub_indication": null,
      "coverage": "entire_revision",
      "modifications_after": "none",
      "explanation_code": "VALID_TIMESTAMPED_UNMODIFIED",
      "explanation": {
        "es_PE": "La firma es válida…",
        "quz_PE": "…"
      }
    }
  ]
}
```
