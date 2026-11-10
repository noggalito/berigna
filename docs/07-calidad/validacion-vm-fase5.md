# Validación en VMs del criterio de salida de la Fase 5

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-007 |
| Versión | 0.1.0 |
| Estado | Borrador |
| Fecha | 2026-11-09 |
| Responsable | noggalito |

## 1. Propósito

Criterio de salida de la Fase 5 (hoja de ruta, BRG-VIS): instalar berigna **desde el repositorio APT publicado**, en máquinas limpias, y repetir allí las pruebas de salida —arranque e integración de escritorio, las dos acciones de la extensión de Nautilus (con un archivo, con varios y con una carpeta) y la firma y verificación con el DNIe real—, además del paso de `piuparts` con los tres paquetes (BRG-DSP-001 §8). Complementa BRG-CAL-006 (validación externa de la Fase 4) y BRG-DSP-001 (empaquetado).

## 2. Entornos

- VMs en KVM (qemu) sobre la estación de trabajo: Debian 13 "trixie" netinst con GNOME (usuario sin `sudo`, con contraseña de root) y Ubuntu 26.04.1 con GNOME.
- Lector Alcor Micro AU9540 (058f:9540), velocidad completa (12 M), por passthrough USB del hipervisor.
- DNIe v2 real; los envíos de PIN siguen BRG-CAL-002.
- Versión probada: 0.3.1-1, publicada en el repositorio el 2026-11-09 (DP-24).

## 3. Debian 13 (criterio cumplido, 2026-11-09)

- Instalación con los cuatro comandos del README, ejecutados como root (`su -`) por la ausencia de `sudo`; huella de la clave comprobada (`A99859F6…`).
- Diagnóstico de berigna en verde de punta a punta: pcscd activo, lector Alcor conectado, DNIe presente, certificado de firma vigente, y confianza y revocación comprobadas en línea (la TSL de INDECOPI descargó y validó en la instalación nueva).
- Extensión de Nautilus: las cuatro comprobaciones pasan (archivo, varios, carpeta, verificar).
- Firma de documentos en PAdES, XAdES y CAdES con el DNIe real, verificación TOTAL-PASSED en berigna y "Resultado válido" en el validador Firma Perú; lotes mixtos con un solo PIN.
- `piuparts -d trixie` con los tres paquetes del release v0.3.1: PASS: All tests (instalación y purga en el chroot prístino), con el único WARN conocido de `python3-reportlab` (enlaces rotos a las DejaVu Condensed, vicio del paquete de Debian, BRG-DSP-001 §8).

El criterio de salida de la Fase 5 queda cumplido en Debian 13, la plataforma objetivo de la v1.

## 4. Ubuntu 26.04.1 (evidencia parcial; pendiente)

- Instalación correcta de la 0.3.1-1 desde el repositorio, con `gir1.2-nautilus-4.1` (Nautilus 50): el arreglo de la API 4.1 publicado en la 0.3.1 funciona.
- La interfaz arranca, el menú contextual de Nautilus funciona, y en una primera pasada se firmaron documentos con el DNIe real (PAdES, XAdES, CAdES y lote mixto), verificados TOTAL-PASSED en berigna y "Resultado válido" en Firma Perú.
- **Pendiente:** repetir la firma con el lector en la VM limpia. El passthrough USB de QEMU deja el dispositivo a medias (véase §5.3): en varias pasadas el kernel del guest lo enumera pero no lo configura (`bConfigurationValue` vacío en sysfs) y pcscd no lo ve. Una pasada en frío funcionó; es intermitente. Queda para la Fase 6, con la redirección USB de SPICE como candidata.

## 5. Hallazgos del entorno de VM (no son defectos de berigna)

### 5.1 Carrera de `postinst` en Ubuntu

Al instalar, el `postinst` de `libccid` intenta arrancar `pcscd.socket` **antes** de que el paquete `pcscd` cree el usuario `pcscd` (`Failed to resolve user 'pcscd'`). Es transitorio: segundos después el `postinst` de `pcscd` levanta el socket sin problema. En Debian 13 no ocurre (el `postinst` de `libccid` no toca pcscd). Reportable upstream como defecto del empaquetado de Ubuntu.

### 5.2 pcscd según la distribución

Ubuntu 26.04 trae pcscd 2.4.1 corriendo como usuario `pcscd`, con autorización polkit (`access_pcsc`) y una regla udev que da el grupo `pcscd` a los lectores CCID (`92-libccid.rules`); Debian 13 trae pcscd 2.3.3 como root, sin polkit ni regla de grupo. En sesiones gráficas ambas funcionan; la polkit de Ubuntu solo afecta a clientes fuera de la sesión activa. El Diagnóstico de berigna es el lugar natural para detectar el socket fallido y sugerir `systemctl reset-failed pcscd.socket`.

### 5.3 Passthrough USB de QEMU

Con hostdev en caliente, el lector queda a medias en el guest (nodo en usbfs sin entrada en sysfs). Con el controlador xHCI emulado, el dispositivo de 12 M se enumera de forma intermitente; con EHCI+UHCI se enumera por UHCI, pero QEMU no completa la configuración del dispositivo (el descriptor dice `bConfigurationValue=1` y sysfs lo deja vacío, por lo que pcscd lo ignora). Una pasada en frío funcionó; la candidata es la redirección USB de SPICE, que trata mejor los lectores de tarjetas. Ninguno de estos síntomas existe en hardware real: el mismo lector firma a diario en la estación de trabajo.

### 5.4 Supuestos de la instalación documentada

Dos supuestos del README cayeron en las VMs limpias y quedan documentados allí: `curl` no viene en Ubuntu (y tampoco siempre en un netinst de Debian), y un usuario de Debian con contraseña de root no tiene `sudo` (los comandos se ejecutan igual desde `su -`).

## 6. Conclusión

El incremento 6 queda cerrado con la Fase 5 (2026-11-09). El criterio de salida se cumple en Debian 13; Ubuntu 26.04 queda con evidencia parcial (instalación, interfaz y Nautilus) y el pendiente del lector en VM anotado para la Fase 6. Los hallazgos de §5 alimentan las mejoras de instalación y del Diagnóstico previstas para la v1.0.
