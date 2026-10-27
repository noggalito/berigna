# Documentación técnica de berigna

| Campo | Valor |
|---|---|
| Documento | BRG-GEN-000 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Propósito

Esta carpeta reúne la documentación técnica pública de berigna: qué debe hacer el software, cómo está diseñado, cómo se protege, cómo se prueba, cómo se desarrolla y cómo se distribuye. Sirve a quienes contribuyen al código y a quienes lo auditan.

La gestión del proyecto (decisiones pendientes, relación con INDECOPI, RENIEC y proveedores, estrategia de acreditación, riesgos y evidencias con datos personales) se lleva en documentación interna que no se publica.

## 2. Estructura

```
docs/
├── README.md                          ← este índice
├── 00-gestion/
│   ├── convenciones-documentales.md   ← identificadores, estados, versionado
│   └── glosario.md
├── 02-marco-normativo/
│   └── estandares-tecnicos.md         ← ETSI, RFC, algoritmos, niveles de firma
├── 03-requisitos/
│   ├── requisitos-funcionales.md      ← RF-xxx
│   ├── requisitos-no-funcionales.md   ← RNF-xxx
│   └── casos-de-uso.md                ← CU-xx
├── 04-arquitectura/
│   ├── arquitectura-general.md
│   ├── flujos-de-firma-y-verificacion.md
│   ├── configuracion-y-datos.md
│   └── adr/                           ← decisiones de arquitectura ADR-xxxx
├── 05-seguridad/
│   ├── modelo-de-amenazas.md
│   └── manejo-de-pin-y-credenciales.md
├── 06-ux/
│   └── diseno-de-interfaz.md
├── 07-calidad/
│   ├── estrategia-de-pruebas.md
│   └── protocolo-pruebas-con-pin.md   ← obligatorio antes de usar un PIN real
├── 08-desarrollo/
│   └── entorno-y-convenciones.md
├── 09-despliegue/
│   └── empaquetado-debian.md
└── 10-investigacion/                  ← spikes SPK-01, SPK-03 y SPK-05
```

Los prototipos de investigación están en [`../spikes/`](../spikes/README.md).

## 3. Orden de lectura recomendado

| Perfil | Documentos |
|---|---|
| Visión general | README raíz → 03-requisitos → 04-arquitectura/arquitectura-general |
| Desarrollador | 03-requisitos → 04-arquitectura → 05-seguridad → 08-desarrollo → 07-calidad |
| Auditor | 02-marco-normativo → 03-requisitos → 04-arquitectura/adr → 05-seguridad → 07-calidad → 10-investigacion |
| Pruebas con un DNIe real | 07-calidad/protocolo-pruebas-con-pin → 10-investigacion/SPK-01 |

## 4. Identificadores de documentación interna

Algunos documentos públicos citan identificadores cuyo detalle está en la documentación interna, no publicada: decisiones de gestión (DP-NN), consultas externas (CE-NN), riesgos (R-NN), requisitos de acreditación (ACR-NN), objetivos y supuestos (OBJ-N, SUP-N), las investigaciones SPK-02 (TSA y servicios de validación) y SPK-04 (normativa y guía de acreditación), y los documentos BRG-VIS (visión y hoja de ruta), BRG-NOR-001 y BRG-NOR-003 (marco legal y acreditación) y BRG-RSG (riesgos). Las conclusiones técnicas que afectan al software están recogidas en los documentos públicos (requisitos, ADR y *spikes*).

## 5. Estado de los documentos

| Carpeta | Estado | Observación |
|---|---|---|
| 00-gestion | Borrador | — |
| 02-marco-normativo | Borrador | — |
| 03-requisitos | Borrador | Línea base para la v1.0 |
| 04-arquitectura | Borrador | ADR-0001 a ADR-0013 aceptados; ADR-0014 (TSL) propuesto |
| 05-seguridad | Borrador | — |
| 06-ux | Borrador | Bocetos de baja fidelidad |
| 07-calidad | Borrador | El protocolo de PIN está Vigente |
| 08-desarrollo | Borrador | — |
| 09-despliegue | Borrador | — |
| 10-investigacion | Cerrado | SPK-01, SPK-03 y SPK-05 cerrados |

## 6. Decisiones técnicas principales

| Tema | Decisión |
|---|---|
| Interfaz | Solo GUI (GTK4 + libadwaita) en la v1; núcleo independiente de la interfaz (ADR-0002) |
| Lenguaje | Python 3 (ADR-0001) |
| Formatos y niveles | PAdES, CAdES y XAdES, de B-B a B-LTA, seleccionables por el usuario (ADR-0007, ADR-0008) |
| Acceso al DNIe v2 | Driver APDU propio sobre PC/SC; PKCS#11 para otros *tokens*; contribución de un driver a OpenSC (ADR-0003, ADR-0012) |
| Certificado para firmar | Solo el de no repudio |
| Nivel por defecto | B-LT si hay TSA y OCSP; si no, B-B con un aviso |
| Dependencias | Las de Debian 13 más pyHanko 0.25.1 empaquetado (ADR-0013) |
| Arquitecturas | Paquetes `Architecture: all`; amd64 con soporte oficial, arm64 sin soporte oficial |
| Idiomas | es_PE y en_US completos (ADR-0011) |
| Distribución | Paquete `.deb` para Debian 13 (ADR-0006) |
| Licencia | GPL-3.0-or-later (ADR-0005) |
