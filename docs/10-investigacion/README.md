# Investigaciones previas (*spikes*)

| Campo | Valor |
|---|---|
| Documento | BRG-INV-000 |
| Versión | 0.2.0 |
| Estado | En curso |
| Fecha | 2026-10-27 |
| Responsable | noggalito |

Los *spikes* se ejecutan en la Fase 0, antes de escribir código de producto. Cada uno tiene una pregunta, un método, un criterio de cierre y una plantilla de resultados. Sus conclusiones actualizan las decisiones pendientes y los ADR.

| ID | Pregunta | Cierra | Prioridad | Estado |
|---|---|---|---|---|
| [SPK-01](SPK-01-identificacion-dnie-y-middleware.md) | ¿Qué DNIe tengo y qué módulo PKCS#11 permite firmar con él en Debian 13? | DP-01, R-01 | Crítica, va primero | Cerrado: DNIe v2 identificado, firma con PIN verificada, dos lectores perfilados, PAdES válido en Firma Perú |
| SPK-02 | ¿Qué TSA y qué servicios OCSP y CRL hay disponibles en la IOFE? | — | Alta | Documentación interna. Conclusiones técnicas públicas: OCSP de RENIEC operativo; la CRL de la CA del DNIe pesa unos 109 MB (RF-063) |
| [SPK-03](SPK-03-viabilidad-cades-xades-python.md) | ¿Se pueden generar y validar CAdES y XAdES de B-B a B-LTA en Python con PKCS#11? | DP-03, ADR-0008 | Alta | Cerrado: PKI de pruebas y DNIe real |
| SPK-04 | ¿Qué exigen la normativa vigente y la guía de acreditación de INDECOPI? | — | Alta | Documentación interna. Conclusiones técnicas públicas: requisitos del software de usuario final (RF/RNF y ADR-0014) |
| [SPK-05](SPK-05-dependencias-en-debian.md) | ¿Qué dependencias Python están en Debian 13 y cuáles hay que empaquetar? | DP-06 | Media | Cerrado (2026-10-27) |
| [SPK-06](SPK-06-dnie-1-0-y-3-0.md) | ¿Qué chip, aplicaciones y ruta de firma tienen el DNIe 1.0 y el DNIe 3.0? | RNF-COM-05 (versión 1.1) | Alta | Pendiente: se necesita acceso a las tarjetas |
