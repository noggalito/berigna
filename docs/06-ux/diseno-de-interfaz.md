# Diseño de interfaz

| Campo | Valor |
|---|---|
| Documento | BRG-UX-001 |
| Versión | 0.7.0 |
| Estado | Borrador (bocetos de baja fidelidad) |
| Fecha | 2026-11-03 |
| Responsable | noggalito |

## 1. Principios de UX

1. Un camino principal obvio: abrir → revisar → firmar → listo.
2. El estado del DNIe siempre está visible: lector, tarjeta y titular.
3. Lenguaje llano: "Firma con sello de tiempo" antes que "B-T". El código técnico aparece como texto secundario.
4. No hay sorpresas legales: el nivel, el certificado y el documento se muestran antes del PIN.
5. Errores accionables: qué pasó, por qué y qué hacer, con un botón hacia el diagnóstico.
6. Cumplimiento de la HIG de GNOME y de libadwaita: `AdwHeaderBar`, `AdwToastOverlay`, `AdwPreferencesDialog`, `AdwStatusPage`.
7. Dos idiomas con el mismo cuidado: cada texto se redacta en es_PE y en quechua con el mismo tono llano. No se traduce palabra por palabra. Los bocetos de §3 están en es_PE; los textos en quechua salen del catálogo, traducción automática en línea apoyada en un glosario propio, y corregidos por personas hablantes en la versión 1.1 (ADR-0015, DP-14; ADR-0011).
8. Diseño para longitudes variables: ninguna etiqueta depende de una anchura fija, porque los textos pueden crecer hasta un 40 % entre idiomas (RNF-USA-08).

## 1.1 Identidad visual

La identidad de berigna está en [`data/brand/`](../../data/brand/README.md) (rehacha el 2026-10-30 con el kit `isotipo`/`isologo`/`logotipo` y la paleta burdeos–rosa antiguo–carbón–niebla), bajo GPL-3.0-or-later como el resto del proyecto (© 2026 noggalito). Por eso el icono puede acompañar al paquete en Debian.

- Paleta: burdeos `#6B2232`, rosa antiguo `#C4868C`, carbón `#2B1E20`, niebla `#F5EAEB`. Contraste del burdeos sobre niebla: 9,4:1, y del carbón sobre niebla: 13,6:1.
- El nombre se escribe siempre en minúsculas: berigna.
- La interfaz usa la tipografía y los colores del sistema (HIG de GNOME, libadwaita), con el color de acento que el usuario eligió en GNOME (decisión del 2026-10-28): la marca no fuerza el burdeos en la interfaz, y vive en el icono, el informe, la web y la firma visible. Las tipografías de la marca (Arvo y Source Sans 3) se reservan para el logotipo y las piezas de comunicación, no para la interfaz.
- El icono de la aplicación (`com.noggalito.Berigna`, a color con relieve, la variante plano para tamaños pequeños y la negra para el simbólico) se rehíce el 2026-10-30 a partir del isotipo nuevo, sin el nombre (BRG-UX-002 §2).

## 2. Mapa de navegación

```mermaid
flowchart LR
  Inicio[Inicio / estado del DNIe] -->|abrir o soltar PDF| Firmar
  Inicio -->|abrir un archivo firmado| Verificar
  Inicio -->|varios archivos| Lote
  Firmar --> Resumen[Resumen + PIN] --> Progreso --> Resultado
  Resultado --> Verificar
  Inicio -. menú .-> Preferencias
  Inicio -. menú .-> Diagnóstico
  Inicio -. menú .-> Historial
  Inicio -. menú .-> Acerca[Acerca de]
```

## 3. Bocetos

### 3.1 Inicio

```
┌──────────────────────────────────────────────────────────────┐
│ ☰                         berigna                       ─ □ ✕ │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│                         [ icono ]                            │
│                                                              │
│              Arrastra aquí un documento para                 │
│                   firmarlo o verificarlo                     │
│                                                              │
│                  [ Abrir documento… ]                        │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ ● DNIe listo · NOMBRE APELLIDO APELLIDO · vence 21/01/2028   │
└──────────────────────────────────────────────────────────────┘
  Estados de la barra inferior:
  ○ Conecta un lector de tarjetas          [Diagnóstico]
  ○ Inserta tu DNIe en el lector
  ⚠ Tarjeta no compatible                  [Más información]
  ⚠ Certificado vencido / revocado
```

### 3.2 Firmar

Implementado en la Fase 3, incremento 3; la firma visible, en el incremento 5 (ADR-0018): una lista de apariencia que empieza por "No visible" (después: solo texto, rúbrica, logotipo o código QR) en el panel, y el recuadro sobre la vista previa, que se mueve arrastrándolo y cambia de tamaño arrastrando su esquina inferior derecha (arrastrar el resto de la página la desplaza, como en un visor de documentos), con el sello dibujado en vivo con datos de muestra; en un recuadro más alto que ancho, la imagen va encima del texto. La vista previa abre en la primera página encajada en la ventana; tiene un campo para escribir el número de página y zoom del 50 % al 400 % (botones y Ctrl + rueda). El recuadro de la firma aparece en la página que se esté viendo y la sigue al cambiar de página (el usuario elige la página libremente; decisión del 2026-10-30). Motivo y ubicación en listas con "Otro". Diferencias con el boceto: los niveles que necesitan una TSA aparecen desactivados mientras no haya una configurada (DP-02); un documento certificado "sin cambios" muestra el motivo y no deja firmar (ERR-307).

```
┌──────────────────────────────────────────────────────────────┐
│ ←  contrato.pdf                                  [ Firmar ]  │
├────────────────────────────────────┬─────────────────────────┤
│                                    │ Nivel de firma          │
│   ┌──────────────────────────┐     │ ◉ Validación a largo    │
│   │                          │     │   plazo (B-LT)          │
│   │   previsualización       │     │ ○ Archivo a largo plazo │
│   │   de la página           │     │   (B-LTA)               │
│   │                          │     │ ○ Con sello de tiempo   │
│   │        ┌────────┐        │     │   (B-T)                 │
│   │        │ firma  │ ←arrastrable │ ○ Básica (B-B)          │
│   │        └────────┘        │     │ ⓘ ¿Qué nivel elegir?    │
│   └──────────────────────────┘     ├─────────────────────────┤
│   ◀  Página 3 de 3  ▶   ─ 100% +   │ Firma visible   [  ●]   │
│                                    │ Apariencia [Rúbrica ▾]  │
│                                    ├─────────────────────────┤
│                                    │ Motivo     [_________]  │
│                                    │ Ubicación  [Lima, Perú] │
│                                    │ ▸ Opciones avanzadas    │
│                                    │   (certificar documento)│
└────────────────────────────────────┴─────────────────────────┘
```

Otros archivos (CU-05; Fase 4, incremento 6). Lo que no es PDF no siempre se puede previsualizar, así que en el lugar de la vista previa se muestran el nombre, el tamaño (legible y exacto en bytes), el tipo (la descripción del escritorio, en el idioma de la interfaz) y el SHA-256 en grupos de cuatro, con la vista del texto debajo si el archivo es de texto (UTF-8, UTF-16 con BOM o la codificación que declare un XML; los primeros 64 kB de un archivo grande, con aviso). El panel propone el formato: XAdES envuelta para un XML y CAdES separada (`.p7s`) para el resto; el usuario puede elegir otra variante (XAdES envolvente o separada `.xsig`, o CAdES envolvente `.p7m`; un XML también se puede firmar en CAdES). En un XML que ya tiene firmas, la envuelta aparece desactivada con el motivo (ERR-312). Cuando una variante estándar choca con Firma Perú, el validador oficial, berigna mantiene el estándar y lo avisa en la descripción de la variante (decisión del titular, 2026-11-03; BRG-CAL-006 §3.10): la CAdES envolvente `.p7m` dice que Firma Perú no reconoce esa extensión y que, para validarla allí, hay que cambiarla a `.p7s` y subir antes el archivo original (que berigna puede guardar desde el `.p7m`); la XAdES separada `.xsig` dice que Firma Perú no la valida y que otros validadores, como DSS, sí. En un lote, el mismo aviso aparece bajo la variante elegida. Motivo, ubicación y firma visible son de PAdES y no aparecen. El diálogo del PIN añade el SHA-256 y el formato.

```
┌──────────────────────────────────────────────────────────────┐
│ ←  planilla.csv                                  [ Firmar ]  │
├────────────────────────────────────┬─────────────────────────┤
│ Archivo para firmar                │ Formato de la firma     │
│ Archivo para firmar en CAdES       │ ◉ CAdES, separada (.p7s)│
│  Nombre   planilla.csv             │ ○ CAdES, envolvente     │
│  Tamaño   1,2 MB (1 234 567 bytes) │   (.p7m)                │
│  Tipo     Documento CSV            ├─────────────────────────┤
│  SHA-256  ABCD 1234 …              │ Nivel de firma          │
│ ┌────────────────────────────────┐ │ ◉ Validación a largo    │
│ │ nombre;monto                   │ │   plazo (B-LT)          │
│ │ Rosa Quispe;100                │ │ …                       │
│ └────────────────────────────────┘ │                         │
└────────────────────────────────────┴─────────────────────────┘
```

### 3.3 Resumen y PIN

Implementado en la Fase 3, incremento 3, con `Gtk.PasswordEntry` (P-05). Tras un PIN incorrecto el diálogo vuelve a aparecer con los intentos restantes (P-07) y el usuario debe escribir y confirmar de nuevo (P-06); con 0 intentos se explica el bloqueo. El campo se vacía en cuanto se toma el PIN.

```
┌───────────────────────────────────────────────┐
│            Confirmar firma                    │
│                                               │
│  Documento   contrato.pdf (3 páginas)         │
│  Firmante    NOMBRE APELLIDO APELLIDO         │
│  DNI         ****5678                         │
│  Nivel       Validación a largo plazo (B-LT)  │
│  Apariencia  Visible, página 3                │
│                                               │
│  PIN del DNIe  [••••••          ]  👁̸         │
│  ⚠ Te queda 1 intento antes del bloqueo       │
│                                               │
│            [ Cancelar ]   [ Firmar ]          │
└───────────────────────────────────────────────┘
```

### 3.4 Resultado de la verificación

Implementado en la Fase 3, incremento 2. Diferencias con el boceto: la explicación de cada firma va bajo su firmante y los detalles técnicos en una fila desplegable; "Verificar de nuevo" es un botón de la barra de título, visible si algún resultado es indeterminado; cada firma permite guardar la versión del documento que dejó (CU-06).

En la Fase 4, incremento 6, la misma página verifica firmas CAdES (`.p7s`, `.p7m`) y documentos XML con firmas XAdES (`.xml`, `.xsig`); el formato se reconoce por el contenido, no por la extensión. Para una firma separada se busca el archivo firmado junto a ella: el que nombra una XAdES (solo el nombre, nunca otra carpeta), el mismo nombre sin la extensión (`acta.xml` para `acta.xml.p7s`) o sin el número que berigna añade cuando el nombre está ocupado (`acta.xml` para `acta-2.xml.p7s`); en CAdES se prefiere el que tiene el resumen firmado. Si no está, la página lo pide ("Elegir archivo…"). El resumen muestra el archivo firmado, que se puede cambiar, y en un `.p7m` la fila "Guardar el contenido firmado" (RF-051). Los detalles técnicos dicen el formato y, en XAdES, qué cubre la firma (todo el documento, una parte, el contenido dentro de la firma o un archivo aparte; AM-06), y cada sello de archivo. Los informes JSON y PDF llevan lo mismo y el nombre y SHA-256 del archivo firmado. "Firmar" sigue disponible en un XML firmado; no aparece en CAdES, porque la cofirma (RF-023) llega después de la 1.0, ni en una firma separada, porque firmaría el archivo de la firma y no el documento.

```
┌──────────────────────────────────────────────────────────────┐
│ ←  informe-firmado.pdf                    [ Exportar ▾ ]     │
├──────────────────────────────────────────────────────────────┤
│  ✔ 2 firmas válidas · El documento no fue modificado         │
│                                                              │
│  ┌ ✔ NOMBRE APELLIDO ──────────────────────────────────────┐ │
│  │ Firmó el 27/10/2026 10:15 (hora certificada por la TSA) │ │
│  │ Nivel B-LT · DNIe · ECEP-RENIEC                         │ │
│  │ ▸ Detalles técnicos                                     │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌ ⚠ OTRO FIRMANTE ────────────────────────────────────────┐ │
│  │ No se pudo comprobar la revocación (sin conexión)       │ │
│  │ Resultado: INDETERMINADO                                │ │
│  │ [ Reintentar en línea ]   ▸ Detalles técnicos           │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### 3.5 Lote

```
┌──────────────────────────────────────────────────────────────┐
│ ←  Firmar 12 archivos                   [ Firmar 12 ]        │
├──────────────────────────────────────────────────────────────┤
│  Archivo                 Formato            Estado           │
│  acta-01.pdf             PAdES visible      ✔                │
│  acta-02.pdf             PAdES visible      ⟳ firmando…      │
│  datos.xml               XAdES envuelta     ·                │
│  planilla.xlsx           CAdES (.p7s)       ·                │
│  …                                                           │
│  [ + Añadir ]  [ − Quitar ]          Nivel: [B-LT ▾]         │
│  ████████████░░░░░░░░  5 / 12   [ Cancelar ]                 │
└──────────────────────────────────────────────────────────────┘
```

Implementado en la Fase 3, incremento 6, con PDF; los demás formatos llegaron en la Fase 4, incremento 6 (RF-041): PAdES para los PDF, XAdES para los XML y CAdES para el resto, según el contenido de cada archivo y no su extensión, con un grupo "Formato de la firma" que deja elegir la variante de los XML y la de los demás archivos (aparece solo si la lista los tiene). Las firmas (`.p7s`, `.p7m`, `.xsig`) nunca entran en un lote, para no firmarlas de nuevo: se avisa de que se verifican una a una. Al añadir una carpeta se dejan fuera también los archivos ocultos; un archivo que no se puede leer se avisa y no entra. Cada fila dice su carpeta y su formato. Se entra con "Firmar varios documentos…" en la pantalla inicial, abriendo o arrastrando varios archivos a la vez, o una carpeta. La lista se construye en la misma página (añadir documentos, añadir una carpeta con o sin subcarpetas, quitar); lo que se firma es cada archivo tal como estaba al añadirlo (su SHA-256). El nivel y los datos de la firma son los de la firma individual. Diferencias con el boceto: la confirmación es el diálogo del PIN, que indica el número de documentos; las firmas del lote no son visibles; los archivos que fallan las comprobaciones previas se informan sin pedir el PIN por ellos; dos archivos del mismo nombre en una misma carpeta de salida se numeran. Resultado: una fila por archivo y los botones "Exportar el informe…" (CSV), "Mostrar en la carpeta" y "Firmar otros documentos", que deja en la lista los que no se firmaron.

## 4. Textos de los niveles (borrador)

| Nivel | Título (es_PE) | Descripción (es_PE) | Title (en_US) | Description (en_US) |
|---|---|---|---|---|
| B-B | Básica | Firma sin sello de tiempo. La fecha la declara tu equipo. | Basic | Signature without a timestamp. The date is declared by your computer. |
| B-T | Con sello de tiempo | Una autoridad de sellado certifica la fecha y la hora de la firma. | With timestamp | A timestamping authority certifies the date and time of the signature. |
| B-LT | Validación a largo plazo | Incluye además la información necesaria para verificar la firma años después. Recomendado. | Long-term validation | Also includes the information needed to verify the signature years from now. Recommended. |
| B-LTA | Archivo a largo plazo | Protege la firma contra la obsolescencia criptográfica. Para documentos que deban conservarse muchos años. | Long-term archival | Protects the signature against cryptographic obsolescence. For documents that must be kept for many years. |

Las columnas en_US se conservan para la versión 1.1. Los textos en quechua se traducen a partir de las columnas es_PE (ADR-0015).

## 4.1 Selector de idioma

En "Preferencias → General → Idioma" se elige entre "Usar el idioma del sistema", "Español (Perú)" y "Runasimi (quechua)". Cada idioma aparece escrito en su propia lengua. El cambio se aplica al momento, sin reiniciar: berigna reconstruye la ventana en el nuevo idioma y vuelve a abrir el documento en curso. El idioma del informe PDF se elige en el propio diálogo de exportación.

## 4.2 Aviso de traducción sin revisar

Hasta que la traducción al quechua tenga corrección humana (versión 1.1, DP-14), berigna lo dice abiertamente:

- Con la interfaz en quechua, la ventana principal muestra un `AdwBanner` con el texto, en quechua y en español, "Traducción sin revisar por hablantes. En caso de duda, prevalece el texto en español" y el botón "Ver en español", que cambia `ui-language` a es_PE (al momento, §4.1). No se puede cerrar: `AdwBanner` admite un solo botón, y el aviso debe seguir visible mientras la interfaz esté en quechua.
- El diálogo del PIN y el resultado de la verificación en quechua incluyen el botón "Leer en español", que muestra el mismo texto en es_PE sin cambiar de idioma (en la verificación, también los detalles técnicos y los sellos de documento). Se llama distinto del "Ver en español" del aviso, que sí cambia el idioma, para que nadie confunda las dos acciones (revisión del 2026-10-29).
- El informe PDF en quechua añade la misma advertencia junto a la nota de prevalencia del español (ADR-0015, punto 7).
- El aviso desaparece en la versión que incorpore la corrección por personas.

## 4.3 Preferencias

Implementado en la Fase 3, incremento 4 (CU-08), como `AdwPreferencesDialog` con tres páginas:

- General: idioma de la interfaz; nivel por defecto, algoritmo de *hash*, sufijo y carpeta de los archivos firmados.
- Red: dirección de la TSA con el botón "Probar"; tiempo de espera; proxy del sistema, manual o ninguno.
- Confianza: estado de la TSL de INDECOPI (secuencia, fechas y número de CA acreditadas) y "Actualizar ahora".

Cambiar el idioma reconstruye la ventana y vuelve a abrir las Preferencias en el nuevo idioma. En las listas desplegables el valor elegido va como subtítulo, completo, y las opciones de la lista se ajustan en varias líneas en vez de cortarse. Las opciones técnicas tienen un botón "Más información" que abre la ayuda en línea de esa versión (ADR-0017). Pendiente: ver el contenido del almacén de confianza (RF-060) y la autenticación con la TSA (RF-062).

## 4.4 Diagnóstico

Implementado en la Fase 3, incremento 6 (CU-07, RF-007). Se abre desde el menú principal ("Diagnóstico") y desde el botón "Diagnóstico" de los errores de lector, tarjeta o certificado; se apila sobre la página actual, de modo que "volver" regresa a ella. Comprueba en orden: servicio `pcscd`, lector, tarjeta, certificado de firma (sin PIN, con aviso si vence en menos de un mes), confianza y revocación en línea, y autoridad de sellado de tiempo. Cada paso muestra ✓, ⚠, ✗ u omitido, con una acción sugerida; los pasos que dependen de uno que falló se omiten. "Copiar el informe" copia el resultado con la versión de berigna y del sistema, sin PIN y con el DNI enmascarado; "Abrir la carpeta del registro" abre `~/.local/state/berigna/logs/` (RF-083).

## 4.5 Historial y certificados de confianza

Implementados en la Fase 3, incremento 6. Historial (RF-082; menú principal → Historial, Ctrl+H): las firmas, las firmas de lote y las verificaciones, la más reciente primero, con búsqueda por nombre, firmante o SHA-256, "Exportar a CSV" y "Borrar el historial" (con confirmación). Se activa o desactiva, y se elige guardar la ruta completa, en Preferencias → General → Historial. Certificados de confianza (RF-060): Preferencias → Confianza, agrupados por origen (incluidos en berigna, de la lista de INDECOPI, añadidos por el usuario), con el papel, la vigencia, la jerarquía y el SHA-256 seleccionable.

## 5. Pendientes

- [x] ~~Prototipo de alta fidelidad (Figma o Penpot) de las cinco vistas.~~ Descartado (2026-10-29): la interfaz ya está implementada; la aplicación real sustituye al prototipo.
- [x] Icono de la aplicación según la guía de iconos de GNOME (BRG-UX-002 §2).
- [ ] Prueba de usabilidad (RNF-USA-06) en la Fase 3.
- [x] Microcopia completa de errores (catálogo `ERR-xxx`, con su mensaje, su causa y la acción sugerida) en es_PE y en quechua (`core.report.explanations`; una prueba exige un mensaje por código y los catálogos completos).
- [x] Aviso de traducción sin revisar en la ventana principal, en el informe PDF en quechua y "Leer en español" en el diálogo del PIN y en el resultado de la verificación (§4.2).
- [x] Glosario terminológico para traductores: el del quechua es BRG-UX-003; el del inglés se hace con la traducción de la versión 1.1.
- [ ] Revisión de las pantallas en quechua para detectar textos que se desborden (las palabras aglutinantes suelen ser largas), durante la prueba de usabilidad (BRG-CAL-005, participantes en quechua).
