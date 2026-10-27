# ADR-0005: Licencia GPL-3.0-or-later

- Estado: Aceptado
- Fecha: 2026-10-27

## Decisión

Todo el código de berigna se publica bajo GPL-3.0-or-later, con cabeceras SPDX (`SPDX-License-Identifier: GPL-3.0-or-later`) en cada archivo fuente.

## Justificación

- La transparencia y la auditabilidad son coherentes con una herramienta de firma con valor legal y facilitan la evaluación para la acreditación.
- El *copyleft* garantiza que las mejoras de terceros sigan siendo libres.

## Consecuencias

- Todas las dependencias deben ser compatibles: MIT, BSD, Apache-2.0, LGPL o GPL. Las previstas lo son (pyHanko MIT, python-pkcs11 MIT, cryptography Apache-2.0/BSD, asn1crypto MIT, lxml BSD, PyGObject LGPL). Se mantiene un inventario (RNF-LEG-02).
- Si alguna vez hace falta un módulo PKCS#11 propietario (DP-01), berigna lo carga dinámicamente como una biblioteca del sistema y no lo distribuye. `[VERIFICAR]` con asesoría legal su compatibilidad con la GPL en ese escenario.
- La acreditación se asocia a builds concretos firmados por el titular (ver BRG-NOR-003 §6).
- Las contribuciones externas requerirán aceptar un DCO (*Developer Certificate of Origin*).
