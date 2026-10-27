# Estrategia de pruebas

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-001 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Objetivos

1. Demostrar que cada requisito "Debe" se cumple (trazabilidad RF/RNF → PR).
2. Demostrar la interoperabilidad con los validadores de referencia.
3. Generar evidencias reutilizables para el expediente de acreditación.
4. Hacer que la mayor parte de las pruebas se ejecute sin hardware, en CI.

## 2. Niveles de prueba

| Nivel | Alcance | Herramientas | ¿En CI? |
|---|---|---|---|
| Unitarias | Funciones y clases de `berigna.core` | pytest, hypothesis | Sí |
| Integración con un *token* simulado | Firma y validación de punta a punta con SoftHSM2 y una PKI de pruebas | pytest, softhsm2, una TSA y un OCSP locales de prueba | Sí |
| Interoperabilidad | Validar las salidas de berigna con validadores externos y validar con berigna las firmas producidas por otros. Una firma solo pasa si la indicación global es TOTAL_PASSED **y** cada sello de tiempo, en el informe detallado, da PASSED (SPK-03 §5) | DSS 6.2 (JAR oficiales de Maven Central con un arnés Java mínimo, sin Docker), ReFirma (manual), Adobe Reader (manual) | Parcial (DSS en CI) |
| Hardware real (HIL) | DNIe y lectores reales | Lista de comprobación manual con un registro de evidencias, siguiendo el [protocolo de pruebas con PIN](protocolo-pruebas-con-pin.md) | No |
| Interfaz | Flujos de la GUI | Pruebas manuales guiadas; automatización con dogtail o AT-SPI, si es viable | Parcial |
| Seguridad | *Fuzzing*, análisis estático, dependencias, corpus de ataques | atheris, bandit, pip-audit, corpus de ataques PDF y XML | Sí |
| Empaquetado | Instalación, actualización, desinstalación y lintian | piuparts, lintian, autopkgtest | Sí |
| Usabilidad | RNF-USA-06 | Sesiones con 5 usuarios | No |
| Internacionalización | es_PE y en_US completos y coherentes (§8) | msgfmt, xgettext, pseudolocalización | Sí |

## 3. Entorno de pruebas sin hardware

### 3.1 PKI de pruebas que imita la IOFE

Se genera con un script reproducible (`tests/pki/build.py`) y nunca se distribuye en el paquete:

```
Raíz de pruebas "ECERNEP-TEST"
 └─ Intermedia "ECEP-RENIEC-TEST"
     ├─ Titular válido (autenticación + no repudio)
     ├─ Titular caducado
     ├─ Titular revocado
     └─ Titular sin no repudio
Raíz "TSA-TEST"
 └─ TSA de pruebas
```

Los perfiles de los certificados (extensiones, políticas, uso de clave, algoritmos) deben reproducir los del DNIe real que se capturen en SPK-01.

### 3.2 Servicios simulados

- TSA local (por ejemplo, el *responder* de pruebas que incluye pyHanko, o `openssl ts`).
- Servidor OCSP local (`openssl ocsp`) y CRL servidas por HTTP.
- Inyección de fallos: tiempo de espera agotado, respuesta mal firmada, estado desconocido.

### 3.3 *Token*

El simulador del *applet* PKI del DNIe v2 está en `tests/sim/dnie_v2.py`. Las pruebas HIL están en `tests/hil/`: las de solo lectura se ejecutan con `BERIGNA_HIL=1 pytest -m hil`, y la de firma con PIN (`tests/hil/firmar_hash_con_pin.py`) la ejecuta a mano el titular, siguiendo el protocolo de PIN.


- *Backend* PKCS#11: SoftHSM2 inicializado por las *fixtures*, con las claves y los certificados de la PKI de pruebas. Se prueba también una variante con `CKA_ALWAYS_AUTHENTICATE` activado.
- Driver del DNIe v2 (ADR-0012): un simulador del *applet* PKI que implementa SELECT, READ BINARY, VERIFY (con contador de intentos), MSE:SET y PSO:CDS sobre una clave de la PKI de pruebas, y una conexión PC/SC simulada. Casos: PIN incorrecto o bloqueado, tarjeta retirada a mitad de la lectura, respuestas mal formadas, e instrucciones fuera de la lista blanca (deben rechazarse antes de enviarse).

## 4. Matriz de cobertura de formatos

| Formato \ Nivel | B-B | B-T | B-LT | B-LTA |
|---|---|---|---|---|
| PAdES invisible | PR-PAD-01 | PR-PAD-02 | PR-PAD-03 | PR-PAD-04 |
| PAdES visible | PR-PAD-05 | PR-PAD-06 | PR-PAD-07 | PR-PAD-08 |
| PAdES firma sucesiva | PR-PAD-09 | — | PR-PAD-10 | PR-PAD-11 |
| PAdES certificación (DocMDP) | PR-PAD-12 | — | PR-PAD-13 | — |
| CAdES separada | PR-CAD-01 | PR-CAD-02 | PR-CAD-03 | PR-CAD-04 |
| CAdES envuelta | PR-CAD-05 | PR-CAD-06 | PR-CAD-07 | PR-CAD-08 |
| XAdES envuelta | PR-XAD-01 | PR-XAD-02 | PR-XAD-03 | PR-XAD-04 |
| XAdES envolvente | PR-XAD-05 | PR-XAD-06 | PR-XAD-07 | PR-XAD-08 |
| XAdES separada | PR-XAD-09 | PR-XAD-10 | PR-XAD-11 | PR-XAD-12 |

Cada celda se ejecuta en tres entornos: (a) SoftHSM en CI, (b) validación con DSS en CI y (c) DNIe real con validación en ReFirma (HIL, antes de cada versión).

## 5. Casos de prueba de dispositivo, validación y sello de tiempo

### 5.1 Dispositivo y certificado (PR-TOK)

| ID | Caso | Esperado |
|---|---|---|
| PR-TOK-01 | Inserción y retiro del lector y de la tarjeta en caliente | Estado actualizado en menos de 2 s (RF-001, RF-002) |
| PR-TOK-02 | Lectura de los certificados del DNIe v2 (simulador y HIL) | Coinciden con la referencia de SPK-01 (RF-003) |
| PR-TOK-03 | Token con certificado de autenticación y de no repudio | Se firma siempre con el de no repudio (RF-004, ACR-15) |
| PR-TOK-04 | Certificado sin nonRepudiation ni digitalSignature | La firma se rechaza (ACR-15) |
| PR-TOK-05 | PIN incorrecto, último intento y bloqueado (solo simulador o SoftHSM) | Mensajes de RF-005; ningún reintento automático |
| PR-TOK-06 | Instrucción fuera de la lista blanca en el driver | Se rechaza antes de enviarse (ADR-0012) |

### 5.2 Validación (PR-VAL)

| ID | Caso | Esperado |
|---|---|---|
| PR-VAL-01 | Documento modificado después de firmar | TOTAL-FAILED (HASH_FAILURE) |
| PR-VAL-02 | Certificado caducado en la fecha de la firma | Rechazo al firmar (RF-006, ACR-14); INDETERMINATE o FAILED al verificar |
| PR-VAL-03 | Certificado revocado antes y después de la firma, con y sin sello de tiempo | Indicación ETSI correcta en cada caso (ACR-13) |
| PR-VAL-04 | Cadena hacia una raíz no confiable | INDETERMINATE (NO_CERTIFICATE_CHAIN_FOUND) |
| PR-VAL-05 | Revocación imposible de comprobar | INDETERMINATE; al firmar solo se permite B-B, con aviso (RF-006) |
| PR-VAL-06 | Algoritmo débil (MD5, SHA-1, RSA 1024) | Advertencia o fallo según ETSI TS 119 312; nunca se usa al firmar (ACR-18) |
| PR-VAL-07 | Corpus de ataques PDF (AM-05) | Detectados (RF-055) |
| PR-VAL-08 | Corpus de ataques XML (AM-06) | Detectados |
| PR-VAL-09 | Firma heredada `adbe.pkcs7.detached` con `revocationInfoArchival` | Se valida (RF-050) |

### 5.3 Sello de tiempo (PR-TSA)

| ID | Caso | Esperado |
|---|---|---|
| PR-TSA-01 | Sello válido de una TSA confiable | PASSED, identificando la TSA (ACR-23) |
| PR-TSA-02 | TSA no confiable | El sello no se acepta |
| PR-TSA-03 | Certificado de la TSA revocado o caducado | Detectado (ACR-23) |
| PR-TSA-04 | La TSA no responde o devuelve un error | Se ofrece reintentar o bajar de nivel con confirmación (ADR-0007) |
| PR-TSA-05 | Huella del sello que no coincide (por ejemplo, un sello de archivo mal calculado) | El sello se marca FAILED aunque la firma sea TOTAL_PASSED (SPK-03 §5) |

## 6. Batería de interoperabilidad (criterio de aceptación de la v1.0)

| ID | Prueba | Resultado esperado |
|---|---|---|
| PR-INT-01 | Matriz completa de §4 firmada con el DNIe real y validada en ReFirma | Todas válidas |
| PR-INT-02 | La misma matriz validada en DSS | TOTAL-PASSED con el nivel correcto |
| PR-INT-03 | PAdES abiertos en Adobe Acrobat Reader (con la raíz de la IOFE como confiable) | "Firma válida" |
| PR-INT-04 | PAdES abiertos en Evince/Papers y Okular | Se muestra la firma; la apariencia es correcta |
| PR-INT-05 | Firmas generadas por ReFirma, validadas en berigna | Mismo resultado que en ReFirma |
| PR-INT-06 | Firmas generadas por DSS, validadas en berigna | Mismo resultado que en DSS |
| PR-INT-07 | Matriz completa validada en el validador oficial Firma Perú (https://apps.firmaperu.gob.pe/web/validador.xhtml; usa DSS y la TSL peruana) | "Resultado válido" con el formato y nivel correctos. Primera evidencia: PAdES B-B del DNIe real, 2026-10-27 |

## 7. Pruebas de seguridad

- *Fuzzing* con atheris de los puntos de entrada de la validación (PDF, CMS, XML), con un mínimo de 24 h acumuladas antes de cada versión mayor.
- Análisis estático con bandit y ruff (reglas de seguridad).
- `pip-audit` y revisión de los avisos de seguridad de Debian para las dependencias de sistema.
- Captura de tráfico (RNF-SEG-03 y RNF-SEG-07).
- Pruebas específicas del PIN (BRG-SEG-002 §4).

## 8. Pruebas de internacionalización (PR-I18N)

| ID | Prueba | Resultado esperado | ¿En CI? |
|---|---|---|---|
| PR-I18N-01 | `msgfmt --check --statistics` sobre `po/es_PE.po` y sobre el manual | 100 % traducido, sin *fuzzy* ni errores de formato | Sí |
| PR-I18N-02 | Detección de cadenas visibles sin marcar con `_()` (análisis estático y `xgettext` comparado con el código) | Ninguna | Sí |
| PR-I18N-03 | Pseudolocalización (textos alargados un 40 % y con acentos) y recorrido de todas las vistas | Sin truncados ni solapamientos | Parcial |
| PR-I18N-04 | Respaldo de idioma: `LANGUAGE=es_MX`, `es_ES`, `fr_FR`, `C` | es_PE, es_PE, en_US y en_US, respectivamente | Sí |
| PR-I18N-05 | Selector de idioma en las preferencias (`ui-language`) | El idioma forzado se aplica tras reiniciar | Manual |
| PR-I18N-06 | Formato de fechas y horas en el resultado de verificación y en el sello visible, en ambos idiomas | Formato regional correcto; zona horaria indicada | Sí |
| PR-I18N-07 | Explicaciones de verificación: cada código ETSI y cada `ERR-xxx` tienen su texto en es_PE y en en_US | Cobertura completa | Sí |
| PR-I18N-08 | Revisión de los textos críticos por personas nativas (RNF-USA-09) | Acta de revisión archivada en las evidencias | No |

Las pruebas de usabilidad (RNF-USA-06) se hacen con participantes hispanohablantes. Se recomienda además al menos una sesión en en_US.

## 9. Registro de evidencias

Cada ejecución de las pruebas de interoperabilidad y de hardware genera un directorio `evidencias/<versión>/<fecha>/` con los archivos firmados, los informes de los validadores, capturas de pantalla y un `resumen.md`. Ese material alimenta el expediente de acreditación.

## 10. Criterios de entrada y salida por versión

- Entrada: todas las pruebas de CI en verde (incluidas las PR-I18N) y ninguna vulnerabilidad conocida alta o crítica.
- Salida: la batería de §6 completa, la HIL ejecutada en al menos dos modelos de lector y en las versiones del DNIe soportadas, y evidencias archivadas.

Parque de lectores para la HIL:

| Alias | Modelo | PIN pad | Estado |
|---|---|---|---|
| Hyperion | Realtek Generic USB2.0-CRW (`0bda:0169`) | Probablemente no | Disponible |
| innovatech | Alcor Micro AU9540 (`058f:9540`) | No | Disponible |
| (por adquirir) | Lector CCID de clase 2 con teclado | Sí | Pendiente (para P-08) |
