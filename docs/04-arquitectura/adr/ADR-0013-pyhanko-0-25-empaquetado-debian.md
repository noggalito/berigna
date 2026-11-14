# ADR-0013: pyHanko 0.25.x empaquetado para Debian 13

- Estado: Aceptado
- Fecha: 2026-11-14
- Origen: DP-06, a partir de SPK-05
- Complementa: ADR-0004 y ADR-0006

## Contexto

pyHanko no está en Debian 13. Su versión actual (0.38.0) exige `pyhanko-certvalidator>=0.33`, `cryptography>=48` y `python-pkcs11~=0.9.3`. Debian 13 trae `pyhanko-certvalidator` 0.26.3, `cryptography` 43.0.0 y `python-pkcs11` 0.7.0. La última versión de pyHanko cuyas dependencias declaradas encajan con Debian 13 es la 0.25.1 (2024-07-18), que pide certvalidator `>=0.26.2,<0.27`, cryptography `>=42.0.1` y python-pkcs11 `~=0.7.0`. La 0.25.3 ya exige certvalidator `>=0.26.5` y cryptography `>=43.0.3`.

## Decisión

- Se empaqueta solo `python3-pyhanko` 0.25.1 (o la 0.25.x más alta compatible) como `.deb` en el repositorio APT del proyecto, construido contra las dependencias oficiales de Debian 13.
- Todas las demás dependencias se toman de Debian.

## Consecuencias

- Mantenimiento mínimo y sin interferir con los paquetes del sistema.
- Se trabaja con una versión de pyHanko de mediados de 2024. Mitigaciones:
  - vigilar los avisos de seguridad de pyHanko y aplicar los parches necesarios a la 0.25.x (riesgo R-15);
  - las funciones que falten en la 0.25.x se implementan en la capa propia `core.formats`, sin modificar pyHanko;
  - volver a evaluar al planificar el soporte de Debian 14, cuando las dependencias se actualicen.
- El firmante de pyHanko para el DNIe v2 se implementa como un `Signer` personalizado (una subclase con `async_sign_raw`) que delega en el driver APDU (ADR-0012), sin usar el módulo PKCS#11 de pyHanko.
- La batería de interoperabilidad (07-calidad §6) debe ejecutarse con exactamente esta versión.
- Extras opcionales de pyHanko 0.25.1 frente a Debian 13:
  - `image-support` (Pillow y python-barcode 0.15.1): disponible.
  - `xmp` (defusedxml): disponible.
  - `opentype`: fonttools está, pero uharfbuzz no. Los sellos visibles usarán las fuentes estándar de PDF o fuentes TrueType sin *shaping* avanzado.
  - `async-http`: pide aiohttp `~=3.9` y Debian trae 3.11. Se usan los *fetchers* síncronos basados en `requests`.
  - `etsi` (xsdata, para el informe de validación XML de ETSI): no está. RF-054 en XML (prioridad "Debería") se implementará en la capa propia o se pospondrá.

## Seguimiento (2026-11-14)

Reevaluación con Debian 14 (forky, todavía *testing*), en SPK-05 §5 y BRG-CAL-008:

- La decisión sigue vigente para Debian 13. En forky, la 0.3.1 no se instala por una sola dependencia: forky trae `python3-pyhanko-certvalidator` 0.30.2 y pyHanko 0.25.1 pide `<0.27` (con la 0.30, pyHanko 0.25.1 ni siquiera se importa). El resto de las dependencias cumple el `Depends`.
- Ninguna versión de pyHanko acepta a la vez la certvalidator de Debian 13 (0.26.3) y la de forky (0.30.2): cada pyHanko pide un rango cerrado. Con la de forky de hoy, la pareja es pyHanko 0.34.x, que además necesita `tzdata-legacy` (zona `CET`) y `cryptography >= 43.0.3`.
- pyHanko 0.25.1 con certvalidator 0.26.3 funciona con las demás bibliotecas de forky y Python 3.14: la suite de la 0.3.1 pasa en una VM con forky, salvo fallos del entorno de prueba (BRG-CAL-008). Con pyHanko 0.34.1 y las bibliotecas de forky, el código casi no cambia: un solo cambio de comportamiento (un CMS hostil sale INDETERMINATE en lugar de TOTAL-FAILED). Pasar de la 0.34 sí exige cambiar código: la 0.35 retiró `pyhanko.sign.validation.ltv`.
- Opciones (SPK-05 §5.4): suites del repositorio por distribución, certvalidator 0.26.3 embebida en `python3-pyhanko`, o esperar el pyHanko oficial de Debian (ITP #1062808, ADR-0020). Sobrescribir la certvalidator de la distribución queda descartado: cambiaría el componente que se acredita en Debian 13 y `python3-xhtml2pdf` depende de ella. La elección está pendiente de decisión del titular (DP-28); si cambia este ADR, se registrará en un ADR nuevo.

