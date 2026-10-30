# Inventario de recursos visuales

| Campo | Valor |
|---|---|
| Documento | BRG-UX-002 |
| Versión | 0.3.0 |
| Estado | Borrador |
| Fecha | 2026-10-30 |
| Responsable | noggalito |

Iconos, ilustraciones y demás piezas gráficas que necesita berigna, para adelantar su diseño. Complementa el diseño de interfaz (BRG-UX-001) y la identidad visual (`data/brand/`).

## 1. Criterios

- Se reutiliza el tema de iconos Adwaita siempre que tenga un icono adecuado. Solo se diseña lo que falta o lo que en Adwaita se entiende mal.
- Guía de iconos de GNOME (HIG). El icono de la aplicación se dibuja a todo color sobre una retícula de 128×128 px. Los simbólicos se dibujan a 16×16 px, en un solo color y con el sufijo `-symbolic`, porque GTK los recolorea según el tema claro u oscuro.
- Formato fuente: SVG, en `data/icons/` y bajo GPL-3.0-or-later como el resto del proyecto (BRG-UX-001 §1.1).
- Las capturas de pantalla, los ejemplos y las ilustraciones nunca muestran datos reales: se usa el firmante ficticio de las pruebas (por ejemplo, "QUISPE MAMANI ROSA FIR ****4321 hard"), nunca un DNI real.
- Prueba de aceptación: `tests/ui/test_application.py::test_every_icon_exists_in_the_theme` comprueba que todo icono usado existe. Al añadir un icono propio se añade a esa lista.

## 2. Icono de la aplicación (rehacer el 2026-10-30 con la identidad nueva)

Se hace desde el isotipo de la marca, sin el nombre: la variante `color` (con relieve) para el icono principal, la `plano` para los tamaños pequeños (el manual ordena usar la plana por debajo del tamaño mínimo del relieve) y la `negro` para el simbólico. Está en `data/icons/`; se instala en `hicolor` y va también en los recursos, de modo que funciona desde el árbol de trabajo.

| Archivo | Tamaño | Origen | Uso |
|---|---|---|---|
| `com.noggalito.Berigna.svg` | Escalable (lienzo de 128×128 px) | Isotipo color (`berigna-isotipo-color.svg`) | Lanzador, "Acerca de", GNOME Software, Flathub, notificaciones |
| `com.noggalito.Berigna-small.svg` | Se instala para 16, 24 y 32 px | Isotipo plano (`berigna-isotipo-plano.svg`) | Listas y tamaños pequeños |
| `com.noggalito.Berigna-symbolic.svg` | 16×16 px | Isotipo negro (`berigna-isotipo-negro.svg`) | Barra superior de GNOME, menú contextual de Nautilus (RF-070) |

Observación: a 24 px la onda y la cola rosa antiguo todavía se leen; por debajo (16 px) las colas se pierden. Si se las quiere más legibles, conviene pedir a la fuente de la marca un "isotipo reducido" (globo con la onda, sin colas finas) para el `-small`; no existe en el manual actual.

Opcional, más adelante: una variante `com.noggalito.Berigna.Devel` con la franja de las aplicaciones de desarrollo de GNOME.

## 3. Prioridad 2: iconos simbólicos propios

Solo los conceptos que Adwaita no cubre o cubre mal. Todos de 16×16 px y monocolor.

| Nombre propuesto | Concepto | Dónde se usa | Qué se usa hoy |
|---|---|---|---|
| `berigna-sign-symbolic` | Firmar (pluma sobre una línea, o rúbrica) | Botón "Firmar" (opcional junto al texto), menú de Nautilus, lote, historial | Nada: botón solo con texto. Adwaita no tiene un icono de firma |
| `berigna-verify-symbolic` | Verificar (documento con una marca de validez) | Acción "Verificar", menú de Nautilus | `security-high-symbolic` (un escudo), que sugiere antivirus |
| `berigna-certificate-symbolic` | Certificado digital | Detalles técnicos, diagnóstico, almacén de confianza en Preferencias | Nada |
| `berigna-timestamp-symbolic` | Sello de tiempo (reloj con sello) | Niveles B-T a B-LTA, preferencias de la TSA | `alarm-symbolic` (un despertador) |
| `berigna-dnie-symbolic` | DNIe (tarjeta con chip y foto) | Barra de estado ("DNIe listo"), diálogo del PIN | `auth-smartcard-symbolic`, una tarjeta genérica |
| `berigna-card-reader-symbolic` | Lector de tarjetas USB vacío | "Conecta un lector de tarjetas", diagnóstico | `media-removable-symbolic`, que parece una memoria USB |
| `berigna-signature-area-symbolic` | Recuadro de firma visible | Activar la firma visible y colocarla sobre la vista previa (incremento 5) | Nada |
| `berigna-seal-symbolic` | Sello institucional | Perfil de apariencia "Sello institucional" (RF-081) | Nada (opcional) |

Decisión del 2026-10-28: estos iconos se preparan según se vayan necesitando. Mientras tanto se usan los de §4 o solo texto.

## 4. Iconos de Adwaita que ya sirven (no hay que diseñarlos)

| Icono | Uso en berigna |
|---|---|
| `object-select-symbolic` | Firma válida, DNIe listo, documento firmado |
| `dialog-warning-symbolic` | Resultado indeterminado, tarjeta no compatible, avisos |
| `dialog-error-symbolic` | Firma no válida, errores |
| `document-open-symbolic` | Página de inicio |
| `x-office-document-symbolic` | Documento sin vista previa, archivo de otro tipo |
| `document-save-symbolic` | Guardar la versión firmada |
| `view-refresh-symbolic` | Verificar de nuevo |
| `go-previous-symbolic`, `go-next-symbolic` | Páginas de la vista previa |
| `content-loading-symbolic` | Buscando lectores |
| `open-menu-symbolic` | Menú principal |
| `dialog-password-symbolic` | Lector con PIN pad, "Introduce tu PIN en el lector" (versión 1.1) |
| `zoom-in-symbolic`, `zoom-out-symbolic`, `zoom-fit-best-symbolic` | Zoom de la vista previa (incremento 5) |
| `view-list-bullet-symbolic` | Lote (incremento 6) |
| `document-open-recent-symbolic` | Historial (RF-082) |
| `network-offline-symbolic` | Sin conexión: revocación no comprobada |
| `preferences-system-symbolic` | Preferencias, diagnóstico |
| `folder-documents-symbolic` | Carpeta de salida en Preferencias |

## 5. Prioridad 3: ilustraciones de las páginas de estado

Hoy las páginas de estado usan el icono simbólico a gran tamaño, como la mayoría de las aplicaciones de GNOME, y funcionan bien así. Unas pocas ilustraciones ayudarían a los usuarios con poca experiencia (RNF-USA-06), sobre todo con el lector:

| Página | Hoy | Propuesta |
|---|---|---|
| Inicio: "Arrastra aquí un documento" | `document-open-symbolic` | Documento con el símbolo de berigna |
| "Inserta tu DNIe en el lector" | Texto en la barra de estado | DNIe entrando en el lector, con el chip hacia el lado correcto. Es la duda más frecuente; sirve también para la ayuda (§9) |
| "Conecta un lector de tarjetas" | Texto en la barra de estado | Lector USB y la flecha hacia el equipo |
| Documento firmado | `object-select-symbolic` | Documento con la marca de firma |
| PIN bloqueado | `dialog-error-symbolic` | Candado sobre el DNIe, con el texto que remite a RENIEC |

Formato: SVG de 128 a 256 px que se vea bien en modo claro y oscuro. Si se hacen simbólicos, el tema los recolorea; si son a color, conviene revisarlos en los dos modos.

## 6. Firma visible (incremento 5; RF-012, RF-081, RF-092)

Hecho el 2026-10-28 (ADR-0018): solo texto, rúbrica, logotipo o código QR; Source Sans 3 para el texto y Arvo Bold para el nombre; tinta carbón con un filete burdeos. Lo que sigue queda como referencia para afinar el diseño.


Es la pieza gráfica que más ven terceros, porque queda impresa en los documentos. Hace falta diseñar:

1. **Plantillas de apariencia** del recuadro, con las variables `{nombre}`, `{dni}`, `{fecha}`, `{motivo}` y `{ubicacion}`:
   - solo texto (la plantilla por defecto);
   - texto con una rúbrica (imagen del usuario a la izquierda o encima);
   - texto con un logotipo (perfil "Sello institucional").
2. **Proporciones y tamaños** de referencia, por ejemplo 180×60 pt y 120×45 pt, y cómo se reajusta el texto si el usuario cambia el tamaño del recuadro.
3. **Tipografía:** debe incrustarse en el PDF y verse igual en Papers, Okular y Acrobat (aceptación de RF-012). Candidatas: DejaVu Sans (ya en Debian y en el informe PDF) o Source Sans 3 (de la marca, licencia OFL).
4. **Textos fijos en es_PE y en quechua** ("Firmado digitalmente por", "Fecha", "Motivo"), con la longitud del quechua en cuenta: las palabras aglutinantes son largas (BRG-UX-001 §5).
5. **Color:** neutro (negro o gris oscuro) para que se imprima bien. El burdeos de la marca, como mucho en un filete.
6. **En la interfaz:** el recuadro de colocación sobre la vista previa (borde, tiradores para redimensionar, estado al arrastrar) y la vista previa en vivo con los datos del certificado (CU-02).

## 7. Informe PDF de verificación

- Cabecera con el isologo horizontal (`berigna-isologo-horizontal-color.svg`). ReportLab no dibuja SVG sin otra biblioteca, así que hace falta una exportación PNG a 300 ppp, o convertir el isologo a trazos que ReportLab dibuje.
- Colores de los resultados: hoy son los de la paleta de GNOME (verde `#26a269`, rojo `#c01c28`, naranja `#c64600`). Hay que decidir si se mantienen o se armonizan con la marca, sin perder la lectura de "válido / no válido / indeterminado" en blanco y negro.

## 8. Color de acento de la interfaz (decidido)

Decisión del 2026-10-28: la interfaz usa el color de acento que el usuario eligió en GNOME, como esperan los usuarios del escritorio, y no fuerza el burdeos de la marca. La marca vive en el icono, el informe, la web y la firma visible. El burdeos `#6B2232` tampoco tendría contraste suficiente sobre el fondo oscuro.

## 9. Ayuda integrada y manuales (RF-091; evidencia ACR-22)

- Capturas de cada caso de uso en es_PE y en quechua, con datos ficticios.
- Esquema "cómo insertar el DNIe en el lector" (puede ser la misma ilustración de §5).
- Esquema de los cuatro niveles de firma (qué añade cada uno), reutilizable en la página de niveles.
- Iconos de la ayuda Mallard: se usan los de §3 y §4.

## 10. Tiendas, repositorio y web (Fase 5 y versión 1.1)

| Pieza | Formato | Para |
|---|---|---|
| Capturas para AppStream | PNG 16:9 (por ejemplo, 1280×800), estilo claro, datos ficticios | GNOME Software (Fase 5) y Flathub (1.1) |
| Colores de marca para AppStream | `<branding>` con un color para el modo claro y otro para el oscuro | Cabecera de berigna en GNOME Software y Flathub |
| Imagen social del repositorio | PNG 1280×640 | Vista previa al compartir el enlace de GitHub |
| Cabecera de la página del repositorio APT | Logotipo horizontal | Página de instalación |

## 11. Orden sugerido

Los iconos y las ilustraciones se preparan según se vayan necesitando (decisión del 2026-10-28). Orden orientativo:

| Orden | Pieza | Lo necesita |
|---|---|---|
| 1 | Plantillas de la firma visible (§6) | Incremento 5 de la Fase 3 |
| 2 | Ilustración "Inserta tu DNIe" (§5) | Revisión de usabilidad (criterio de salida de la Fase 3) y ayuda |
| 3 | Iconos de §3, cuando una pantalla los pida | Incrementos 5 y 6; menú de Nautilus en la Fase 5 |
| 4 | Logotipo y colores del informe (§7) | Fase 3, según dé tiempo |
| 5 | §9 y §10 | Fases 5 y 6; Flathub en la 1.1 |
