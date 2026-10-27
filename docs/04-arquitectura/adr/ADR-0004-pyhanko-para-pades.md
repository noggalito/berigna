# ADR-0004: pyHanko como motor PAdES

- Estado: Aceptado (sujeto a la verificación de SPK-03 y SPK-05)
- Fecha: 2026-10-27

## Contexto

Se necesita generar y validar PAdES en los niveles B-B a B-LTA, con firma visible, firmas incrementales, DocMDP, DSS/VRI y sellos de documento, y además firmar con un *token* PKCS#11.

## Decisión

Usar pyHanko (licencia MIT) junto con sus componentes `pyhanko-certvalidator` (validación de cadenas y revocación) y su integración PKCS#11 (basada en `python-pkcs11`).

## Justificación

- Implementa PAdES en todos los niveles de línea base, sellos de documento, inserción de datos de validación (DSS) y validación.
- Tiene soporte nativo para firmar con PKCS#11.
- Permite personalizar los sellos visibles.
- Está activamente mantenido y bien documentado.

## Alternativas

- endesive (MIT): más simple, pero con menos cobertura de LTV y validación.
- Implementación propia sobre pikepdf + asn1crypto: costosa y arriesgada.
- DSS (Java) como servicio auxiliar: contradice ADR-0001 y añade una JVM.

## Consecuencias

- Hay que fijar la versión y seguir sus cambios de API.
- Hay que comprobar en SPK-05 si está empaquetado en Debian 13; si no, se empaqueta (DP-06).
- La API CMS genérica de pyHanko también sirve de base para CAdES (ADR-0008).
