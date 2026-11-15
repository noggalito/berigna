# SPK-05: Dependencias en Debian 13

| Campo | Valor |
|---|---|
| Documento | BRG-INV-005 |
| Versión | 0.3.0 |
| Estado | Cerrado (2026-10-27) |
| Fecha | 2026-11-14 |
| Responsable | noggalito |

## 1. Método

```bash
for p in <paquetes>; do
  printf '%-34s ' "$p"; apt-cache policy "$p" | awk '/Candidate|Candidato/ {print $2}'
done
```

Además se consultaron en PyPI las dependencias declaradas por cada versión de pyHanko.

## 2. Resultados (Debian 13 trixie, 2026-10-27)

| Dependencia | ¿En Debian 13? | Versión en Debian | Uso | Acción |
|---|---|---|---|---|
| pyHanko | No | — | PAdES y CMS | Empaquetar la 0.25.1 (ADR-0013) |
| pyhanko-certvalidator | Sí | 0.26.3-2 | Validación de cadenas | Usar la de Debian |
| python-pkcs11 | Sí | 0.7.0-1+b5 | *Backend* PKCS#11 | Usar la de Debian |
| pyscard | Sí | 2.2.2-1 | Driver APDU del DNIe v2 (ADR-0012) | Usar la de Debian |
| signxml | Sí | 4.0.5+dfsg-2 | XAdES (ADR-0008, candidata) | Usar la de Debian; viabilidad en SPK-03 |
| asn1crypto | Sí | 1.5.1-3 | ASN.1 | Debian |
| cryptography | Sí | 43.0.0-3+deb13u1 | Criptografía | Debian |
| lxml | Sí | 5.4.0-1 | XML | Debian |
| Pillow | Sí | 11.1.0-5+deb13u4 | Imágenes del sello | Debian |
| requests | Sí | 2.32.3 | HTTP (TSA, OCSP, CRL) | Debian |
| aiohttp | Sí | 3.11.16 | No se usa (pyHanko 0.25.1 pide ~=3.9) | — |
| click, qrcode, tzlocal, pyyaml, defusedxml, python-barcode, fonttools | Sí | 8.1.8, 8.2, 5.3.1, 6.0.2, 0.7.1, 0.15.1, 4.57.0 | Dependencias de pyHanko | Debian |
| uharfbuzz | No | — | Extra `opentype` de pyHanko | No se usa |
| xsdata | No | — | Extra `etsi` de pyHanko (informe XML) | No se usa en la v1 |
| pypdfium2 | No | — | Previsualización (alternativa) | Poppler-GLib (en Debian) es la candidata; la decisión se toma en la Fase 3 con un ADR (arquitectura §8) |
| reportlab | Sí | 4.3.1 | Informe PDF | Debian |
| babel | Sí | 2.17.0 | Formatos regionales (ADR-0011) | Debian |
| PyGObject | Sí | 3.50.0 | GUI | Debian |
| GTK 4 / libadwaita | Sí | 4.18.6 / 1.7.6 | GUI | Debian |
| Poppler-GLib (GIR) | Sí | 25.03.0 | Previsualización de PDF | Debian |
| blueprint-compiler | Sí | 0.16.0 | Construcción de la UI | Debian |
| nautilus-python | Sí | 4.0.1 | Extensión de Nautilus | Debian |
| opensc / opensc-pkcs11 | Sí | 0.26.1 | *Backend* PKCS#11 (no reconoce el DNIe v2) | Recommends |
| softhsm2 | Sí | 2.6.1 | Pruebas | Solo en desarrollo |

### 2.1 Disponibilidad en arm64 (comprobada el 2026-10-27, para DP-08)

Fuente: `https://qa.debian.org/madison.php?package=<p>&s=trixie&a=arm64`.

| Paquete | Versión en trixie |
|---|---|
| python3-gi | 3.50.0-4+b1 (arm64) |
| gir1.2-gtk-4.0 | 4.18.6+ds-2 (arm64) |
| gir1.2-adw-1 | 1.7.6-1~deb13u1 (arm64) |
| gir1.2-poppler-0.18 | 25.03.0-5+deb13u4 (arm64) |
| python3-pyscard | 2.2.2-1 (arm64) |
| python3-pkcs11 | 0.7.0-1+b5 (arm64) |
| python3-cryptography | 43.0.0-3+deb13u1 (arm64) |
| python3-lxml | 5.4.0-1 (arm64) |
| pcscd / libccid | 2.3.3-1 / 1.6.2-1 (arm64) |
| python3-nautilus | 4.0.1-2 (arm64) |
| opensc-pkcs11 | 0.26.1-2 (arm64) |
| python3-signxml / python3-pyhanko-certvalidator / python3-asn1crypto | `all` |

## 3. Compatibilidad de las versiones de pyHanko con Debian 13

| pyHanko | Publicada | certvalidator | cryptography | python-pkcs11 | ¿Encaja con Debian 13? |
|---|---|---|---|---|---|
| 0.25.1 | 2024-07-18 | >=0.26.2,<0.27 | >=42.0.1 | ~=0.7.0 | Sí |
| 0.25.3 | 2024-11-17 | >=0.26.5,<0.27 | >=43.0.3 | ~=0.7.0 | No (certvalidator 0.26.3 y cryptography 43.0.0 se quedan cortos) |
| 0.28.0 / 0.29.0 | 2025-05 | >=0.27,<0.28 | >=43.0.3 | ~=0.7.0 | No |
| 0.38.0 | actual | >=0.33,<0.34 | >=48.0.0 | ~=0.9.3 | No |

## 4. Decisión

DP-06 queda cerrada con ADR-0013: se empaqueta pyHanko 0.25.1 como `.deb` en el repositorio del proyecto y todo lo demás se toma de Debian.

## 5. Seguimiento: Debian 14 "forky" (2026-11-14)

Reevaluación prevista por ADR-0013 ("volver a evaluar al planificar el soporte de Debian 14"), hecha sobre Debian *testing* (forky) y PyPI el 2026-11-14. Las versiones de *testing* cambian hasta la congelación: esta tabla es una foto de ese día. La prueba de berigna 0.3.1 en una VM con forky está en [BRG-CAL-008](../07-calidad/validacion-vm-forky.md).

### 5.1 Dependencias de berigna en forky

| Dependencia | Debian 13 | forky (2026-11-14) | ¿Cumple el `Depends` de la 0.3.1? |
|---|---|---|---|
| python3 | 3.13 | 3.14 | Sí |
| GTK 4 / libadwaita / Poppler-GLib | 4.18.6 / 1.7.6 / 25.03.0 | 4.24.1 / 1.10.0 / 26.07.0 | Sí |
| python3-pyscard | 2.2.2 | 2.3.2 | Sí |
| python3-cryptography | 43.0.0 | 49.0.0 | Sí |
| python3-asn1crypto | 1.5.1 | 1.5.1 | Sí |
| python3-lxml | 5.4.0 | 6.1.3 | Sí |
| python3-signxml | 4.0.5 | 4.4.0 | Sí |
| python3-requests / python3-pil / python3-reportlab | 2.32.3 / 11.1.0 / 4.3.1 | 2.34.2 / 12.3.0 / 5.1.0 | Sí |
| python3-oscrypto / python3-uritools (dependencias de certvalidator) | 1.3.0 / 4.0.3 | 1.3.0 / 6.1.3 | Sí |
| pcscd / libccid / opensc-pkcs11 | 2.3.3 / 1.6.2 / 0.26.1 | 2.5.2 / 1.8.4 / 0.27.1 | Sí |
| **python3-pyhanko-certvalidator** | **0.26.3** | **0.30.2** | **No** (`<< 0.27~`) |
| pyHanko | No está | No está | Del repositorio del proyecto |

`apt-get -s` confirma que la 0.3.1 se rechaza en forky solo por `python3-pyhanko-certvalidator`: las otras 35 dependencias que faltaban en la máquina se resuelven con los paquetes de forky.

### 5.2 Ninguna pyHanko sirve a la vez para Debian 13 y forky

Cada versión de pyHanko pide un rango cerrado de certvalidator (PyPI, 2026-11-14):

| pyHanko | certvalidator | cryptography | Python |
|---|---|---|---|
| 0.25.1 | >=0.26.2,<0.27 | >=42.0.1 | >=3.8 |
| 0.29.0 | >=0.27,<0.28 | >=43.0.3 | >=3.9 |
| 0.30.0 | >=0.28,<0.29 | >=43.0.3 | >=3.9 |
| 0.31.0 a 0.33.0 | >=0.29,<0.30 | >=43.0.3 | >=3.9 |
| 0.34.x | >=0.30,<0.31 | >=43.0.3 | >=3.10 |
| 0.35.0 / 0.36.0 | >=0.31,<0.32 (0.36: >=0.31.2) | >=47 / >=48 | >=3.10 |
| 0.37.0 | >=0.32,<0.33 | >=48 | >=3.10 |
| 0.38.1 | >=0.33,<0.34 | >=48 | >=3.11 |

Con la certvalidator de cada distribución, Debian 13 solo admite pyHanko 0.25.x y forky, hoy, solo la 0.34.x. Si forky llega a la certvalidator 0.33 antes de congelarse, la pareja pasa a ser pyHanko 0.38.

### 5.3 Otras restricciones para una pyHanko más nueva en Debian

- pyHanko 0.34 (y las siguientes) crea la zona horaria `CET` al importarse (`pyhanko/sign/validation/qualified/assess.py`). En Debian 13 y en forky, `CET` está en `tzdata-legacy`, no en `tzdata`: sin ese paquete, importar `pyhanko.sign.validation.ades` falla con `ZoneInfoNotFoundError`. Un `python3-pyhanko` 0.34 o posterior debe depender de `tzdata-legacy`, o corregir el nombre de la zona.
- pyHanko 0.34 pide `cryptography >= 43.0.3`, y Debian 13 trae la 43.0.0.
- pyHanko 0.35 retiró `pyhanko.sign.validation.ltv` (la 0.34.1 todavía lo trae), del que berigna importa `retrieve_adobe_revocation_info` (`core.validation.pdf`): pasar de la 0.34 exige cambiar código.
- signxml 4.0.5 (Debian 13) no se importa con cryptography 50 (PyPI): usa la curva `SECT163K1`, que cryptography 50 retiró.
- `python3-xhtml2pdf` depende de `python3-pyhanko-certvalidator` en Debian 13 y en forky: sustituir la certvalidator de la distribución por otra versión desde el repositorio del proyecto afectaría a ese paquete.

### 5.4 Opciones para forky

| Opción | Qué es | Efecto en Debian 13 | Coste estimado |
|---|---|---|---|
| A. Suites por distribución | pyHanko 0.25.1 en una suite para trixie y 0.34.x en otra para forky; un solo `berigna` con el código y el `Depends` válidos para los dos rangos | Ninguno en ejecución; nueva versión de `berigna` que hay que volver a probar. Cambia la suite única del repositorio (BRG-DSP-001 §4) y el archivo `.sources` del paquete `noggalito-archive-keyring` | 1 a 1,5 semanas |
| B. Sobrescribir certvalidator | Publicar certvalidator 0.30 y pyHanko 0.34 para todas las distribuciones | Cambia el núcleo criptográfico de la plataforma que se acredita y puede romper `python3-xhtml2pdf` | Descartada |
| C. Embeber certvalidator | `python3-pyhanko` lleva certvalidator 0.26.3 en una carpeta privada que solo carga berigna | Ninguno en la práctica: el código de certvalidator es el mismo; cambia desde dónde se carga. Incompatible con la política del archivo oficial (ADR-0020) y amplía R-15 a certvalidator | 2 a 4 días |
| D. Esperar el pyHanko oficial | Cuando el pyHanko de Debian (ITP #1062808) llegue a *testing*, berigna se adapta a esa versión | Ninguno hasta la adaptación | La adaptación del código (§5.3) |

La elección es del titular (DP-28). Las opciones A, C y D no son excluyentes: C o A pueden cubrir forky mientras llega D.

