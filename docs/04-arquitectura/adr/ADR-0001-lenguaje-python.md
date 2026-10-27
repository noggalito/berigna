# ADR-0001: Python como lenguaje del proyecto

- Estado: Aceptado
- Fecha: 2026-10-27

## Contexto

Hace falta un lenguaje que permita implementar PAdES, CAdES y XAdES en todos los niveles de línea base, acceder a PKCS#11 y construir una GUI nativa de GNOME, con un equipo pequeño y la intención de acreditar el software. Se evaluaron Python, Rust, Java y C/C++.

## Decisión

Python 3, en la versión que trae Debian 13.

## Alternativas consideradas

| Opción | A favor | En contra |
|---|---|---|
| Rust | Seguridad de memoria, binario nativo | El ecosistema PAdES y LTV es inmaduro; habría que escribir mucha criptografía de formato propia |
| Java (DSS de la UE) | El motor AdES más completo; mismo stack que ReFirma | JVM pesada; integración pobre con GNOME; empaquetado en Debian complejo |
| C/C++ | Control total | Costo y riesgo muy altos en el análisis de formatos |

## Consecuencias

- Positivas: pyHanko ofrece PAdES hasta B-LTA con soporte PKCS#11 y validación. PyGObject da acceso completo a GTK4 y libadwaita. El desarrollo es rápido.
- Negativas: la limpieza de secretos en memoria es limitada (ver 05-seguridad/manejo-de-pin). XAdES en niveles altos tiene menos opciones maduras (ver ADR-0008). Algunas dependencias no están empaquetadas en Debian (DP-06).
- Mitigaciones: tipado estricto (`mypy --strict`), *fuzzing* con Atheris y dependencias auditadas.
