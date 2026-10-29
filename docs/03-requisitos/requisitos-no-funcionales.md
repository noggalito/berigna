# Requisitos no funcionales

| Campo | Valor |
|---|---|
| Documento | BRG-REQ-002 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | noggalito |

Identificadores: `RNF-<CATEGORÍA>-NN`.

## 1. Seguridad (SEG)

| ID | Requisito | Prioridad | Verificación |
|---|---|---|---|
| RNF-SEG-01 | La clave privada nunca sale del chip. Todas las operaciones con la clave privada se delegan al *token*: mediante PKCS#11 (*backend* genérico) o mediante el driver APDU del DNIe v2 (PSO:CDS, ADR-0012) | Debe | Revisión de diseño y de código |
| RNF-SEG-02 | El PIN no se almacena, no se registra y no se transmite fuera del proceso salvo hacia el *token* (*backend* PKCS#11 o driver APDU). Se borra de la memoria al terminar la sesión, en la medida en que el entorno lo permita | Debe | Revisión de código; PR-SEG con inspección de registros |
| RNF-SEG-03 | Los documentos no se envían a ningún servicio de red. Solo salen de la máquina los *hash* hacia la TSA, los identificadores de certificados hacia OCSP y las descargas de CRL y AIA | Debe | Prueba con captura de tráfico |
| RNF-SEG-04 | Todas las conexiones salientes usan HTTPS cuando el servicio lo ofrece. Las respuestas OCSP, CRL y TSA se validan criptográficamente, sea cual sea el transporte | Debe | PR-VAL |
| RNF-SEG-05 | El análisis de archivos no confiables (PDF, XML, CMS) es robusto ante entradas maliciosas: no colapsa la aplicación y está libre de XXE y de expansión de entidades | Debe | *Fuzzing* (07-calidad §7) |
| RNF-SEG-06 | Las dependencias de terceros están fijadas a versiones concretas y se auditan contra vulnerabilidades conocidas en cada versión que se publica | Debe | CI con `pip-audit` o similar |
| RNF-SEG-07 | No hay telemetría ni conexiones no solicitadas | Debe | Captura de tráfico en reposo |
| RNF-SEG-08 | El paquete y el repositorio APT están firmados con GPG y la compilación es reproducible | Debe | `reprotest` y verificación de la firma APT |
| RNF-SEG-09 | La aplicación funciona sin privilegios de root. Solo la instalación los requiere | Debe | Prueba manual |
| RNF-SEG-10 | La extensión de Nautilus solo transmite rutas a la aplicación, sin ejecutar lógica criptográfica en el proceso de Nautilus | Debe | Revisión de diseño |

## 2. Fiabilidad (FIA)

| ID | Requisito | Prioridad |
|---|---|---|
| RNF-FIA-01 | Ninguna operación deja archivos de salida parciales o corruptos (escritura atómica) | Debe |
| RNF-FIA-02 | El retiro del lector o de la tarjeta durante una operación se gestiona sin bloquear la interfaz | Debe |
| RNF-FIA-03 | Los fallos de red (TSA u OCSP) se notifican con reintentos limitados y tiempos de espera configurables (10 s por defecto) | Debe |
| RNF-FIA-04 | Las operaciones largas no bloquean el hilo de la interfaz | Debe |

## 3. Rendimiento (REN)

Valores objetivo en un equipo de referencia (4 núcleos, 8 GB de RAM, SSD), sin contar la latencia de red ni la del chip:

| ID | Requisito | Objetivo |
|---|---|---|
| RNF-REN-01 | Arranque de la aplicación hasta la ventana usable | ≤ 1,5 s |
| RNF-REN-02 | Preparación y escritura de una firma PAdES B-B de un PDF de 10 MB | ≤ 2 s |
| RNF-REN-03 | Verificación de un PDF de 10 MB con 3 firmas usando los datos embebidos | ≤ 3 s |
| RNF-REN-04 | Previsualización de la primera página de un PDF de 100 páginas | ≤ 1 s |
| RNF-REN-05 | Consumo de memoria al firmar un PDF de 100 MB | ≤ 500 MB |

Nota: el tiempo de la operación criptográfica dentro del chip (medido: unos 0,3 s por firma con el DNIe v2, SPK-01 §8.6) se mide y se informa aparte.

## 4. Usabilidad y accesibilidad (USA)

| ID | Requisito | Prioridad |
|---|---|---|
| RNF-USA-01 | La interfaz cumple la guía de interfaz de GNOME (HIG) y usa los componentes de libadwaita | Debe |
| RNF-USA-02 | La interfaz es totalmente operable con el teclado | Debe |
| RNF-USA-03 | Es compatible con el lector de pantalla Orca: todos los controles tienen nombres accesibles | Debe |
| RNF-USA-04 | Respeta el tema claro u oscuro, el escalado y el contraste alto del sistema | Debe |
| RNF-USA-05 | Los mensajes de error indican qué ocurrió, por qué y qué puede hacer el usuario, sin jerga | Debe |
| RNF-USA-06 | Un usuario nuevo completa CU-01 sin ayuda externa en la prueba de usabilidad (al menos 4 de 5 participantes) | Debe |
| RNF-USA-07 | La interfaz está completa en es_PE y en quechua sureño; ninguna cadena visible queda sin traducir en ninguno de los dos idiomas (ADR-0011, ADR-0015). en_US, en la versión 1.1 | Debe |
| RNF-USA-08 | El diseño soporta textos un 40 % más largos que el texto fuente sin truncarlos ni solaparlos (se comprueba con pseudolocalización) | Debe |
| RNF-USA-09 | Los textos críticos para la seguridad y para el resultado legal (diálogo del PIN, resumen de la firma, resultados de verificación, advertencias) los revisa en ambos idiomas una persona nativa, para que no cambien de significado. En quechua, desde la versión 1.1 (DP-14, 2026-10-28) | Debe |

## 5. Compatibilidad (COM)

| ID | Requisito | Prioridad |
|---|---|---|
| RNF-COM-01 | Debian 13 (trixie) en amd64 | Debe |
| RNF-COM-02 | Sesiones Wayland y X11 | Debe |
| RNF-COM-03 | GNOME como escritorio principal; en otros escritorios funciona sin la integración específica con Nautilus | Debe |
| RNF-COM-04 | Lectores USB CCID de contacto genéricos admitidos por `libccid`. Probados: Realtek `0bda:0169` ("Hyperion") y Alcor Micro AU9540 `058f:9540` ("innovatech"). Las necesidades de hardware de prueba, como un lector con PIN pad, están en 07-calidad §10 | Debe |
| RNF-COM-05 | Versiones del DNIe: DNIe v2 en la versión 1.0; DNIe 1.0 y DNIe 3.0 en la versión 1.1 (decisión del 2026-10-27; identificación en SPK-06) | Debe |
| RNF-COM-06 | arm64: el paquete es `Architecture: all` y funciona, pero sin soporte oficial ni pruebas HIL en la v1 (DP-08) | Podría |
| RNF-COM-07 | Ubuntu LTS actual (por compartir base Debian), sin soporte oficial | Podría |

## 6. Interoperabilidad (INT)

| ID | Requisito | Prioridad |
|---|---|---|
| RNF-INT-01 | Las firmas que genera berigna se validan correctamente en el validador web de la Plataforma Nacional de Firma Digital – Firma Perú (PCM-SGTD), referencia oficial desde que RENIEC dejó de distribuir ReFirma a terceros (respuesta del 2026-10-28), y en ReFirma cuando se disponga de él. Evidencia actual: PAdES B-B válido en Firma Perú (SPK-03 §7) y en ReFirma (2026-10-28) | Debe |
| RNF-INT-02 | Las firmas que genera berigna se validan correctamente en un validador conforme a ETSI EN 319 102-1 (por ejemplo, DSS) | Debe |
| RNF-INT-03 | Las firmas PAdES se muestran como válidas en Adobe Acrobat Reader cuando la raíz de la IOFE está en su almacén de confianza | Debe |
| RNF-INT-04 | berigna valida correctamente las firmas que generan ReFirma y otros programas acreditados | Debe |

## 7. Mantenibilidad (MAN)

| ID | Requisito | Prioridad |
|---|---|---|
| RNF-MAN-01 | El núcleo (`berigna.core`) no depende de GTK y se puede ejecutar y probar sin interfaz | Debe |
| RNF-MAN-02 | Cobertura de pruebas del núcleo de al menos el 80 % de líneas y del 100 % de las rutas críticas de firma y validación | Debe |
| RNF-MAN-03 | Anotaciones de tipos completas, verificadas con `mypy --strict` en el núcleo | Debe |
| RNF-MAN-04 | Política de seguridad publicada (`SECURITY.md`) con un canal de reporte y plazos de respuesta | Debe |
| RNF-MAN-05 | Cada decisión de arquitectura relevante se registra como ADR | Debe |

## 8. Legal y licencias (LEG)

| ID | Requisito | Prioridad |
|---|---|---|
| RNF-LEG-01 | Todo el código es GPL-3.0-or-later, con cabeceras SPDX en cada archivo. El repositorio incluye el texto íntegro en `LICENSE`, y la ventana "Acerca de" (`Adw.AboutDialog`, `license_type = GPL_3_0`) y la metainfo de AppStream (`project_license`) la declaran | Debe |
| RNF-LEG-02 | Todas las dependencias tienen licencias compatibles con GPL-3.0 y están inventariadas | Debe |
| RNF-LEG-03 | Hasta obtener la acreditación, ningún texto afirma que el software está acreditado | Debe |
| RNF-LEG-04 | Se cumple la ley de protección de datos personales (tratamiento local y mínimo, ver BRG-NOR-001 §2.3) | Debe |
