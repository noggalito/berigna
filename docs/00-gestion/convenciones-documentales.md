# Convenciones documentales

| Campo | Valor |
|---|---|
| Documento | BRG-GES-001 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Idioma y formato

- La documentación del proyecto (esta carpeta `docs/`) se redacta en español (variante Perú) y en Markdown (CommonMark + tablas GFM).
- La documentación dirigida al usuario final (manual, aviso legal, política de privacidad, notas de versión, metainfo de AppStream) se publica en es_PE y en en_US (DP-07, ADR-0011). En caso de discrepancia prevalece la versión es_PE.
- Notación de idiomas: en los documentos y en gettext se usan los códigos POSIX `es_PE` y `en_US`; en AppStream y en HTML, las etiquetas BCP 47 `es-PE` y `en-US`.
- Los diagramas se escriben en Mermaid dentro del propio Markdown, para que se puedan versionar como texto.
- Los términos técnicos que no tienen una traducción establecida se mantienen en inglés y en cursiva la primera vez que aparecen (por ejemplo, *token*, *spike*). Se definen en el [glosario](glosario.md).

## 2. Cabecera obligatoria

Cada documento empieza con una tabla de control con estos campos: Documento (código), Versión, Estado, Fecha y Responsable.

Códigos de documento: `BRG-<ÁREA>-<NNN>`.

| Área | Prefijo |
|---|---|
| General | GEN |
| Gestión | GES |
| Visión | VIS |
| Normativa | NOR |
| Requisitos | REQ |
| Arquitectura | ARQ |
| Seguridad | SEG |
| UX | UX |
| Calidad | CAL |
| Desarrollo | DES |
| Despliegue | DSP |
| Investigación | INV |
| Riesgos | RSG |

## 3. Estados de un documento

| Estado | Significado |
|---|---|
| Borrador | En elaboración; puede cambiar sin aviso |
| En revisión | Congelado y en revisión por un tercero |
| Aprobado | Línea base; los cambios requieren una nueva versión y una entrada en el historial |
| Obsoleto | Reemplazado; se conserva por trazabilidad |

Estados para tipos de documento específicos:

| Tipo | Estados | Uso |
|---|---|---|
| Registros (decisiones, riesgos, consultas, índice de ADR) | Vivo | Se actualizan de forma continua; los cambios quedan versionados en git |
| Investigaciones (SPK) | Pendiente, En curso, Cerrado | Cerrado: el criterio de cierre se cumplió o su desviación está justificada dentro del propio SPK |
| Procedimientos operativos (por ejemplo, el protocolo de PIN) | Vigente | Procedimiento aprobado y de cumplimiento obligatorio |

El README raíz describe la fase del proyecto (por ejemplo, "fase de especificación"), no el estado de un documento.

## 4. Versionado

Se usa versionado semántico por documento: `MAYOR.MENOR.PARCHE`.

- MAYOR: cambia el alcance o se rompe la trazabilidad (por ejemplo, se renumeran requisitos).
- MENOR: se añade contenido (requisitos, secciones).
- PARCHE: correcciones de redacción.

Cuando un documento pasa a Aprobado, se le añade una sección final "Historial de cambios".

## 5. Identificadores trazables

Los identificadores son estables: nunca se reutilizan ni se renumeran. Un elemento eliminado se marca como `[RETIRADO]`.

| Prefijo | Elemento | Ubicación |
|---|---|---|
| RF-NNN | Requisito funcional | 03-requisitos/requisitos-funcionales.md |
| RNF-CAT-NN | Requisito no funcional (CAT: SEG, FIA, REN, USA, COM, INT, MAN, LEG) | 03-requisitos/requisitos-no-funcionales.md |
| CU-NN | Caso de uso | 03-requisitos/casos-de-uso.md |
| ADR-NNNN | Decisión de arquitectura | 04-arquitectura/adr/ |
| AM-NN | Amenaza | 05-seguridad/modelo-de-amenazas.md |
| CS-NN | Control de seguridad | 05-seguridad/ |
| PR-ÁREA-NN | Caso de prueba (áreas TOK, VAL, TSA, INT, I18N en 07-calidad; SEG en 05-seguridad junto al control que verifica; PAD, CAD y XAD en la matriz de 07-calidad §4) | 07-calidad/ y 05-seguridad/ (y luego en el código de pruebas) |
| SPK-NN | Investigación previa (*spike*) | 10-investigacion/ |
| SUP-N | Supuesto del proyecto | Documentación interna (visión y alcance) |
| CE-NN | Consulta externa (INDECOPI, RENIEC, TSA) | Documentación interna (consultas externas) |
| R-NN | Riesgo | Documentación interna (registro de riesgos) |
| DP-NN | Decisión pendiente | Documentación interna (decisiones pendientes) |
| ACR-NN | Requisito de acreditación | Documentación interna (acreditación INDECOPI) |

Los identificadores marcados como "documentación interna" se gestionan en un repositorio privado del proyecto; los documentos públicos pueden citarlos, pero no enlazarlos.

## 6. Prioridad de requisitos (MoSCoW)

| Valor | Significado |
|---|---|
| Debe | Imprescindible para la v1.0 |
| Debería | Importante; solo se pospone con justificación escrita |
| Podría | Deseable si hay capacidad |
| No (v1) | Fuera de la v1; está en la hoja de ruta |

## 7. Marcadores en el texto

- `{{TITULAR}}`: nombre del titular o responsable del proyecto, pendiente de definir (DP-05).
- `{{URL_REPOSITORIO}}`: URL del repositorio APT del proyecto (09-despliegue), pendiente de definir.
- `{{CONTACTO}}`: medio de contacto del titular en las consultas externas.
- `{{CONTACTO_SEGURIDAD}}`: dirección para reportes de vulnerabilidades (`SECURITY.md`), pendiente de definir.
- `SPDX-FileCopyrightText: 2026 Calú`: titular provisional de las cabeceras de licencia hasta cerrar DP-05; se sustituirá en bloque.
- `[VERIFICAR]`: afirmación que debe contrastarse con una fuente oficial o con una prueba antes de pasar el documento a Aprobado.
