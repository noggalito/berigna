# SPK-05: Dependencias en Debian 13

| Campo | Valor |
|---|---|
| Documento | BRG-INV-005 |
| Versión | 0.2.1 |
| Estado | Cerrado (2026-10-27) |
| Fecha | 2026-10-28 |
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
