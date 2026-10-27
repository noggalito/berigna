# SPK-01: Identificación del DNIe y del middleware PKCS#11

| Campo | Valor |
|---|---|
| Documento | BRG-INV-001 |
| Versión | 0.4.0 |
| Estado | Cerrado (2026-10-27): firma con PIN verificada (§8.6); PAdES B-B del DNIe real válido en DSS y en el validador oficial Firma Perú (SPK-03 §7) |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Pregunta

¿Qué versión de DNIe y qué lector tenemos? ¿Existe un módulo PKCS#11 que funcione en Debian 13 y permita leer los certificados y firmar con la clave de no repudio?

## 2. Advertencias antes de empezar

- El PIN del DNIe se bloquea tras unos pocos intentos fallidos. Durante este *spike* solo se introduce el PIN cuando se sabe con certeza cuál es, y nunca dentro de un bucle o un *script* que reintente.
- Ninguno de los pasos 3.1 a 3.5 necesita el PIN.
- No se publica en ningún lugar la salida completa de los comandos: contiene el nombre y el DNI del titular. Antes de guardarla en el repositorio se enmascaran esos datos.

## 3. Procedimiento

### 3.1 Preparar el sistema

```bash
sudo apt install pcscd libccid pcsc-tools opensc opensc-pkcs11
sudo systemctl enable --now pcscd.socket
systemctl status pcscd.socket
```

### 3.2 Identificar el lector

```bash
lsusb                                  # anotar el ID del fabricante y del producto del lector
pcsc_scan -r                           # lista los lectores que ve pcscd
opensc-tool --list-readers
```

Resultado esperado: el lector aparece en ambas listas. Si no aparece, se revisa que el lector sea CCID y la salida de `journalctl -u pcscd`.

### 3.3 Identificar la tarjeta (ATR)

Con el DNIe insertado:

```bash
pcsc_scan                              # muestra el ATR y, si lo conoce, el modelo de chip (Ctrl+C para salir)
opensc-tool --atr
opensc-tool --name                     # driver de OpenSC que reconoce la tarjeta, si hay alguno
```

### 3.4 Ver qué expone OpenSC

```bash
MOD=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
pkcs11-tool --module "$MOD" --list-slots
pkcs11-tool --module "$MOD" --list-objects
pkcs11-tool --module "$MOD" --list-mechanisms
pkcs15-tool --dump
```

### 3.5 Extraer y analizar los certificados

Con OpenSC (si reconoce la tarjeta):

```bash
pkcs11-tool --module "$MOD" --read-object --type cert --id <ID> -o cert-<ID>.der
openssl x509 -inform DER -in cert-<ID>.der -noout -text
```

Con el DNIe v2, OpenSC no sirve (ver §8). Los certificados se leen con APDU de lectura (ver §8.4).

### 3.6 y 3.7 Pasos con PIN

Ejecutados con el procedimiento adaptado al DNIe v2 (resultados en §8.6).

### 3.8 Firma PAdES mínima con pyHanko

Hecha en SPK-03 §7: PAdES B-B con el DNIe real, válido en DSS 6.2 y en el validador Firma Perú.

## 4. Qué hacer si OpenSC no reconoce el DNIe

Se evalúan en este orden y se documenta el resultado de cada opción:

1. Comprobar si una versión más reciente de OpenSC (de `trixie-backports` o compilada) incorpora el driver.
2. Buscar un middleware PKCS#11 oficial para Linux publicado por RENIEC o por el fabricante del chip, y revisar su licencia y si se puede redistribuir.
3. Comprobar si la tarjeta es compatible con algún driver genérico de OpenSC mediante `opensc.conf`.
4. Valorar el desarrollo de un driver (para OpenSC o propio) si las especificaciones están disponibles.

Resultado de la evaluación (2026-10-27):

| Opción | Resultado |
|---|---|
| 1. OpenSC más reciente | La 0.26.1 (Debian 13) da "Unsupported card". Las notas de la 0.27.1 (2026-03-31) no mencionan el DNIe peruano. En el repositorio de OpenSC solo constan incidencias del DNIe v1 (Oberthur, controlador IAS-ECC), por ejemplo la #1147 de 2017 |
| 2. Middleware de RENIEC para Linux | No se encontró ninguno publicado |
| 3. Driver genérico de OpenSC | El *applet* PKI no responde a los AID de PKCS#15, IAS-ECC, PIV ni a los de otros *applets* PKI conocidos (§8.3) |
| 4. Driver propio | Viable: el protocolo es ISO 7816-4 estándar y sencillo, y está implementado en el proyecto MIT [peru-dnie](https://github.com/edeustua/peru-dnie) (§8.4). Decisión: ADR-0012 |

## 5. Identificación de la versión del DNIe

Se cruzan el ATR, la descripción de `pcsc_scan`, el aspecto físico y la información pública de RENIEC. Resultado en §8.1.

## 6. Plantilla de resultados (completada)

| Campo | Valor |
|---|---|
| Fecha de ejecución | 2026-10-27 |
| Lectores (modelo, ID USB) | "Hyperion": Realtek "Generic USB2.0-CRW" combinado, `0bda:0169`. "innovatech": Alcor Micro AU9540, `058f:9540`. Ambos CCID con `libccid` 1.6.2 (comparación en §8.5) |
| ATR | `3B DC 18 FF 81 91 FE 1F C3 80 73 C8 21 13 66 05 03 63 51 00 02 50` |
| Descripción del chip (`smartcard_list.txt`) | "JCOP3 SecID P60 CS (JavaCard)": NXP JCOP3 (CPLC: fabricante del IC 0x4790 = NXP) |
| Versión del DNIe | DNIe versión 2 (el ATR coincide exactamente con `PERU_DNIE_V2_ATR` del proyecto peru-dnie). ATR por NFC según ese proyecto: `3B 80 80 01 01` |
| Versión de OpenSC | 0.26.1 (Debian 13) |
| ¿Driver de OpenSC reconocido? | No: "Unsupported card" |
| *Applets* detectados | GlobalPlatform ISD `A0 00 00 01 51 00 00 00` (seleccionado por defecto); ICAO eMRTD `A0 00 00 02 47 10 01`; PKI `E8 28 BD 08 0F D2 50 "Generic"` (ASCII) |
| Número de certificados y su uso | 3. Firma (archivo `001D`, *keyUsage* nonRepudiation); autenticación (`001C`, digitalSignature, EKU clientAuth + smartcardLogon); cifrado (`001B`, keyEncipherment + dataEncipherment) |
| Emisor | `C=PE, O=Registro Nacional de Identificación y Estado Civil, CN=ECEP-RENIEC CA Class 2 II` |
| Cadena completa | ECERNEP PERU CA ROOT 3 → ECEP-RENIEC → ECEP-RENIEC CA Class 2 II → titular. `openssl verify`: OK |
| OID de la política | Comunes: `1.3.6.1.4.1.35300.2.1.3.1.0.101.1000.0`, `1.3.6.1.4.1.35300.2.1.3.1.0.103.1000.0`, `0.4.0.2042.1.2` (ETSI NCP+). Por certificado: firma `…2.103.1001.2`, autenticación `…2.103.1002.2`, cifrado `…2.103.1004.2` |
| URL de OCSP | `http://ocsp.reniec.gob.pe` (funciona; ver SPK-02) |
| URL de CRL | `http://crl.reniec.gob.pe/crl/sha2/caclass2ii.crl` y `http://crl2.reniec.gob.pe/crl/sha2/caclass2ii.crl` |
| URL de AIA (emisor) | `http://crl.reniec.gob.pe/crt/sha2/caclass2ii.crt` (y crl2) |
| Algoritmo y tamaño de clave | RSA 2048; certificados firmados con sha256WithRSAEncryption |
| Vigencia de los certificados | 4 años (en la muestra: del 2024-01-22 al 2028-01-21). Los tres certificados se emitieron el mismo día |
| Mecanismo de firma | El chip aplica el relleno PKCS#1 v1.5: recibe `DigestInfo` (OID del *hash* + *hash*) calculado fuera de la tarjeta. Equivale a `CKM_RSA_PKCS` sobre un DigestInfo |
| Referencias de PIN | 0x81 (firma, verificada) y 0x83 (cifrado, según peru-dnie). `[VERIFICAR]` si existe un PIN de autenticación distinto |
| Persistencia del VERIFY entre firmas | Sí: un VERIFY permite varias PSO:CDS, aunque se repita el MSE:SET o se vuelva a seleccionar el *applet*. Solo se pierde al apagar o reiniciar la tarjeta (§8.6) |
| ¿Firma de prueba verificada? | Sí: 4 firmas RSA PKCS#1 v1.5 con SHA-256, verificadas con `cryptography` y con `openssl dgst -verify` |
| ¿PAdES B-B válido en un validador oficial? | Sí, en el validador Firma Perú (PCM) y en DSS 6.2 (SPK-03 §7). ReFirma: pendiente como prueba de interoperabilidad (PR-INT-01) |
| Tiempo de la operación de firma en el chip | PSO:CDS unos 277 ms; VERIFY 40 ms; MSE:SET 26 ms (lector "Hyperion") |
| Conclusión | DP-01 cerrada con ADR-0012: driver APDU propio en Python y, en paralelo, contribución de un driver a OpenSC |

## 7. Criterio de cierre

DP-01 queda cerrada con un módulo identificado y una firma PAdES B-B hecha con el DNIe real que ReFirma da por válida. Estado: cumplido con una desviación justificada. La validación se hizo en el validador oficial del Estado, Firma Perú (PCM; basado en DSS y con la TSL peruana), en lugar de ReFirma, porque ReFirma no está disponible en Linux (consulta CE-07). Validar en ReFirma queda como prueba de interoperabilidad (PR-INT-01, RNF-INT-01) y no como condición de cierre de este *spike*.

## 8. Detalle de la ejecución (2026-10-27)

### 8.1 Entorno

- Debian 13, `pcscd` 2.3.3 activo por *socket*, `libccid` 1.6.2.
- Las herramientas `opensc`, `opensc-pkcs11`, `pcsc-tools` y `python3-pyscard` no estaban instaladas. Se descargaron con `apt-get download` y se ejecutaron desde un directorio temporal, sin instalarlas en el sistema.

### 8.2 OpenSC

```
$ opensc-tool --list-readers
0    Yes             Generic USB2.0-CRW [Smart Card Reader Interface] (20070818000000000) 00 00
$ opensc-tool --atr
3b:dc:18:ff:81:91:fe:1f:c3:80:73:c8:21:13:66:05:03:63:51:00:02:50
$ opensc-tool --name
Unsupported card
```

### 8.3 Sondeo de *applets* (solo SELECT y GET DATA; no afectan al PIN)

| Comando | Respuesta |
|---|---|
| SELECT ICAO eMRTD `A0000002471001` | 9000 |
| SELECT GP ISD `A000000151000000` / SELECT sin AID | 9000, FCI con AID `A000000151000000` |
| GET DATA CPLC `80 CA 9F 7F` | 9000 (CPLC de NXP) |
| SELECT IAS-ECC, PKCS#15, PIV, eSign (CEN), IDPrime, Belgian eID, SmartCard-HSM, OpenPGP, IsoApplet, etc. | 6A82 (no existe) |
| SELECT por FID (MF, 2F00, 5015) con el ISD seleccionado | 6A86: el ISD no tiene sistema de archivos |
| SELECT PKI `E828BD080FD250` + `"Generic"` | 9000 |

### 8.4 Protocolo del *applet* PKI del DNIe v2

Las operaciones sin PIN se verificaron el 2026-10-27. Las operaciones con PIN se tomaron de peru-dnie (MIT) y se verificaron el 2026-10-27 (§8.6).

| Paso | APDU | Verificado |
|---|---|---|
| Seleccionar el *applet* PKI | `00 A4 04 00 0E E8 28 BD 08 0F D2 50 47 65 6E 65 72 69 63` | Sí |
| Seleccionar un certificado | `00 A4 02 04 02 00 1D` (firma), `00 1C` (autenticación), `00 1B` (cifrado) | Sí |
| Leer el certificado | READ BINARY con INS impar: `00 B1 00 00 04 54 02 <offset_hi> <offset_lo> FF`. La respuesta va envuelta en `53 81 xx`. Se lee en bloques de 0xE4 bytes hasta SW `6282` (fin de archivo). El archivo ocupa 4096 bytes con relleno; el certificado se recorta usando la longitud de su cabecera DER | Sí |
| Verificar el PIN de firma | `00 20 00 81 <Lc> <PIN ASCII>` | Sí (2026-10-27) |
| MSE:SET (firma, relleno en la tarjeta) | `00 22 41 B6 06 80 01 8A 84 01 81` | Sí |
| PSO: COMPUTE DIGITAL SIGNATURE | `00 2A 9E 9A <Lc> <DigestInfo>` (sin Le); devuelve 256 bytes. Sin autenticación responde `6982` | Sí |

### 8.5 Comparación de lectores (2026-10-27)

Los lectores se identifican con alias internos del proyecto. Mismo DNIe v2 en ambos y solo comandos de lectura.

| Aspecto | "Hyperion" | "innovatech" |
|---|---|---|
| Modelo / USB | Realtek "Generic USB2.0-CRW", `0bda:0169` (combinado SD + tarjeta inteligente) | Alcor Micro AU9540 "EMV Smartcard Reader", `058f:9540` |
| Nombre PC/SC | `Generic USB2.0-CRW [Smart Card Reader Interface] (20070818000000000) 00 00` | `Alcor Micro AU9540 00 00` |
| Soporte en `libccid` 1.6.2 | Sí (está en `Info.plist`) | Sí |
| Protocolos / negociado | T=0 y T=1 / T=1 | T=0 y T=1 / T=1 |
| PIN pad | No (`bPINSupport 0`; parte 10 solo anuncia `GET_TLV_PROPERTIES`) | No (igual) |
| Nivel de intercambio CCID / velocidad máx. | TPDU (`dwFeatures 0x00010030`) / 312 500 bps | APDU corta y extendida (`dwFeatures 0x000404BE`) / 688 172 bps |
| ATR del DNIe | `3B DC 18 … 02 50` | Idéntico |
| OpenSC 0.26.1 | Unsupported card | Unsupported card |
| Certificados leídos | 3 | 3, idénticos byte a byte (mismo SHA-256) |
| Latencia de un SELECT | Mediana 28,5 ms | Mediana 28,8 ms |
| Lectura de un certificado completo | Unos 1 028 ms (18 APDU); 667 ms parando en la longitud DER | Unos 1 020 ms (18 APDU, archivo entero de 4096 B) |

Aprendizajes:

1. El comportamiento de la tarjeta no depende del lector. El ATR, los *applets*, los certificados y la falta de soporte en OpenSC son propiedades del DNIe v2. Esto confirma que el *backend* se elija por el ATR y no por el lector (ADR-0012), y que el lector sea solo un transporte PC/SC.
2. Los nombres de los lectores en PC/SC son arbitrarios y cambian con el modelo. berigna no debe guardar en su configuración el lector por su nombre: elige el primero que contenga una tarjeta con un ATR soportado y, si hay varios, pregunta al usuario (RF-001).
3. Con ninguno de los dos lectores se puede probar el PIN pad. La ruta P-08 (`FEATURE_VERIFY_PIN_DIRECT`) necesita un lector de clase 2 con teclado para las pruebas HIL.
4. El tamaño de cada bloque de lectura lo limita la tarjeta, no el lector: aunque "innovatech" admite APDU extendidas, el *applet* devuelve como máximo 231 B por READ BINARY (3 B de cabecera + 0xE4 de datos). El driver mantiene bloques de 0xE4.
5. Optimización de la lectura: el driver lee hoy el archivo entero (18 APDU, unos 1 s por certificado), pero el certificado ocupa unos 2,4 KB. Si se para al alcanzar la longitud indicada en la cabecera DER, bastan unas 11 APDU (estimado: unos 0,6 s), y conviene guardar los certificados en caché mientras la tarjeta siga insertada.
6. El cambio de lector en caliente funcionó sin reiniciar `pcscd`, lo que es coherente con RF-001.
7. Aunque "innovatech" tiene más del doble de velocidad máxima e intercambio por APDU (frente a TPDU), los tiempos son iguales. El cuello de botella es el procesamiento de la tarjeta, no el lector.

### 8.6 Prueba de firma con PIN (2026-10-27, lector "Hyperion")

La ejecutó el titular en su propia terminal: un único VERIFY, sin reintentos. Se firmaron textos de prueba, no documentos.

| Paso | SW | Tiempo | Resultado |
|---|---|---|---|
| VERIFY PIN 0x81 | 9000 | 40 ms | — |
| MSE:SET | 9000 | 26 ms | — |
| Firma 1 | 9000 | 277 ms | Verificada |
| Firma 2: sin VERIFY ni MSE | 9000 | 278 ms | Verificada |
| Firma 3: MSE sin VERIFY | 9000 | 277 ms | Verificada |
| Re-SELECT del *applet* y firma 4 sin VERIFY | 9000 | 277 ms | Verificada |
| Después, desde otro proceso: SELECT + MSE + PSO sin VERIFY | 6982 | — | No autenticada |

Conclusiones:

1. El DNIe v2 firma correctamente con el protocolo documentado. Es una firma RSA PKCS#1 v1.5 de 256 B; la tarjeta añade el relleno sobre el `DigestInfo`.
2. Un solo VERIFY permite firmar varias veces. La firma por lotes con un único PIN (RF-040) es viable.
3. Volver a seleccionar el *applet* no cierra la sesión de seguridad. El único "logout" fiable es reiniciar o apagar la tarjeta (`SCardDisconnect` con `SCARD_RESET_CARD` o `SCARD_UNPOWER_CARD`).
4. La sesión se cerró en la prueba solo porque pyscard usa por defecto `SCARD_UNPOWER_CARD` al desconectarse. Si un programa se desconecta con `SCARD_LEAVE_CARD`, la tarjeta queda autenticada y cualquier proceso con acceso a PC/SC podría firmar sin PIN. Esto se convierte en una regla obligatoria del driver (ADR-0012 y AM-01).
5. Mientras la sesión está autenticada, otro proceso podría firmar si la conexión es compartida. El driver debe usar `SCARD_SHARE_EXCLUSIVE` (o una transacción PC/SC) durante toda la sesión de firma.
6. Tiempo de la tarjeta por firma: unos 0,3 s. Un lote de 50 firmas ocupa unos 15 s de tarjeta, más el trabajo de PDF y de red.

## 9. Pendientes (requieren el PIN del titular)

Estas pruebas debe ejecutarlas el titular del DNIe, con su PIN, una sola vez y sin reintentos:

1. Pendiente: consultar los intentos restantes del PIN con `00 20 00 81` sin datos (VERIFY sin datos devuelve `63Cx` según ISO 7816-4). Hay que confirmar antes con el titular que la tarjeta no cuenta esta consulta como intento fallido.
2. Hecho (§8.6).
3. Hecho (§8.6): la autenticación persiste.
4. Hecho (§8.6): unos 277 ms.
5. Hecho (SPK-03 §7): PAdES B-B con el DNIe real, válido en DSS 6.2 y en el validador oficial Firma Perú.
6. Hecho con "innovatech" en SPK-03: PSO:CDS de 275, 274 y 278 ms, igual que con "Hyperion" (unos 277 ms).

Pendientes sin PIN:

7. Probar los dos lectores conectados a la vez (selección del lector, RF-001). El perfil de "Hyperion" ya está completo (§8.5).
8. Conseguir un lector con PIN pad (clase 2) para probar P-08.
