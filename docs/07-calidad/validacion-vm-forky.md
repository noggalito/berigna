# Prueba de berigna en Debian 14 "forky"

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-008 |
| Versión | 0.1.0 |
| Estado | Borrador |
| Fecha | 2026-11-14 |
| Responsable | noggalito |

## 1. Propósito

Medir qué le falta a berigna para funcionar en Debian 14 (forky), que hoy es Debian *testing*, con el paquete publicado y los paquetes reales de forky, y no solo con la CI semanal de *testing* (BRG-DES-001 §5). Es la reevaluación que ADR-0013 prevé para Debian 14. Las versiones y las opciones están en SPK-05 §5; esta es la evidencia de la prueba. No forma parte de ningún criterio de salida: forky no es una plataforma soportada.

## 2. Entorno

- VM en KVM con Debian *testing* (forky), instalada desde la imagen oficial del 2026-11-09, con GNOME 51 en Wayland: Python 3.14.10, kernel 7.2.15+deb14, 4 vCPU y 7,7 GiB de RAM. Usuario sin `sudo`.
- Sin lector de tarjetas: la VM no tiene passthrough USB y `pcscd` no está instalado.
- Versión probada: 0.3.1-1 del repositorio APT del proyecto (`berigna`, `berigna-nautilus` y `python3-pyhanko` 0.25.1-1); el SHA-256 de los tres coincide con el índice `Packages`. Las pruebas son las de la etiqueta `v0.3.1`.

## 3. Método (sin instalar nada en el sistema)

1. `apt-get -s install` de los `.deb` del proyecto: la simulación no necesita root y dice qué dependencia falta.
2. Descarga de las dependencias de forky con `apt-get download` (la lista sale de otra simulación) y de `python3-pyhanko-certvalidator` 0.26.3-2 desde el archivo de Debian 13.
3. Dos raíces desempaquetadas con `dpkg -x` en una carpeta del usuario, con los mismos paquetes de berigna y de forky:
   - **a**, con la certvalidator 0.30.2 de forky;
   - **b**, con la 0.26.3 de Debian 13, que imita llevarla embebida (SPK-05 §5.4, opción C).
4. Ejecución con `PYTHONPATH`, `LD_LIBRARY_PATH`, `GI_TYPELIB_PATH`, `BERIGNA_RESOURCES`, `BERIGNA_LOCALEDIR` y `GSETTINGS_SCHEMA_DIR` apuntando a cada raíz. El esquema de GSettings se compila aparte (`glib-compile-schemas`), porque sin instalación no corre el *trigger* que lo hace.

## 4. Resultados

| Prueba | Resultado |
|---|---|
| `apt-get -s install` de la 0.3.1 | Rechazada: `python3-pyhanko` pide `python3-pyhanko-certvalidator (< 0.27)` y forky trae la 0.30.2. Las otras 35 dependencias que faltaban se resuelven |
| Importar el núcleo con la raíz a (certvalidator 0.30.2) | Falla: `No module named 'pyhanko_certvalidator._asyncio_compat'` |
| Importar el núcleo con la raíz b (certvalidator 0.26.3) | Correcto |
| Suite de la `v0.3.1` con la raíz b (pytest 9.1.1) | 714 pasan, 3 fallan y 6 se omiten (la interfaz con Xvfb y las pruebas con hardware) |
| Interfaz en la sesión Wayland con la raíz b | Arranca, carga la TSL de INDECOPI y sigue abierta 15 s sin errores; GTK funciona sin aceleración (la VM no tiene GPU con 3D) |

Los tres fallos de la suite son del entorno de prueba, no de berigna:

- `test_po_has_no_pending_entries[es_PE]` y `[quz]`: ejecutan `msgfmt` con `PATH=/usr/bin:/bin` fijo, y en la prueba `gettext` estaba desempaquetado en otra carpeta.
- `test_hooks_record_in_the_installed_folder_and_still_print`: con pytest 9, su *plugin* de excepciones en hilos (`threadexception`) intercepta el `threading.excepthook` que la prueba espera ver imprimir. Con `-p no:threadexception` pasan las 8 pruebas del archivo; con el pytest fijado por el proyecto (8.3.5, `scripts/requisitos-pruebas.txt`) pasa. Es la prueba la que hay que adaptar (R-DES-23).

Contraste en la estación de trabajo (Debian 13, Python 3.13, entorno aislado), con las bibliotecas de forky instaladas desde PyPI (cryptography 49, signxml 4.4, lxml 6.1):

| pyHanko y certvalidator | Resultado |
|---|---|
| 0.25.1 y 0.26.3 | 789 pasan; 3 fallan: las dos comprobaciones de versiones del entorno y `test_crashes` (el mismo caso de pytest) |
| 0.34.1 y 0.30.2, con el paquete `tzdata` de PyPI | 787 pasan; 5 fallan: tres comprobaciones de versiones, `test_crashes` y un cambio real de comportamiento: un CMS hostil que lanza una excepción en la construcción de la cadena sale INDETERMINATE en lugar de TOTAL-FAILED (`tests/unit/core/validation/test_pdf.py`, `test_hostile_cms_past_the_digest_is_a_format_failure`) |
| 0.34.1 y 0.30.2, sin la zona `CET` | 29 módulos de pruebas no se cargan: `ZoneInfoNotFoundError: 'No time zone found with key CET'` (SPK-05 §5.3) |

## 5. Hallazgos

1. El único bloqueo de berigna en forky es `python3-pyhanko-certvalidator` (SPK-05 §5.2). El código de berigna no mostró ningún problema con Python 3.14, cryptography 49, signxml 4.4, lxml 6.1, GTK 4.24 ni libadwaita 1.10.
2. Con la certvalidator 0.26.3 al alcance de berigna, la 0.3.1 funciona en forky sin cambios de código.
3. Sin el esquema de GSettings compilado, berigna aborta (`GLib-GIO-ERROR`, volcado de memoria) en lugar de decir qué falta, como sí hace con los recursos. En una instalación con apt no ocurre, pero es la clase de fallo que debería explicarse (R-DES-24). El registro local de fallos (R-DES-11) lo detectó y avisó en el arranque siguiente.
4. Probar en una VM sin `sudo` es posible con `apt-get -s` y `dpkg -x`; para la firma con el DNIe hace falta el passthrough USB del lector (BRG-CAL-007 §5.3).

## 6. Lo que no se probó

- La firma con el DNIe y PIN (sin lector en la VM).
- La instalación real con apt: los *triggers*, el `postinst` y la extensión de Nautilus.
- `piuparts` contra forky.
- Las firmas en Firma Perú y ReFirma desde forky.
