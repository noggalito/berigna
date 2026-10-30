# ADR-0018: Apariencia de la firma visible

- Estado: Aceptado
- Fecha: 2026-10-30
- Origen: Fase 3, incremento 5 (CU-02; RF-012, RF-092); decisiones del titular del 2026-10-28. Carbón al valor `#2B1E20` del manual de marca del 2026-10-30

## Contexto

La firma visible queda impresa en los documentos y la ven terceros. El titular decidió que el usuario elija entre solo texto, una rúbrica precargada, un logotipo precargado o un código QR; que el QR lleve los datos de la firma y la dirección de una página que explique cómo verificarla; y que la tipografía siga la marca de berigna (Arvo y Source Sans 3).

pyHanko dibuja apariencias, pero su motor de texto con tipografías propias necesita uharfbuzz, que Debian no empaqueta; sin él solo usa Courier sin incrustar. Debian trae Source Sans 3 únicamente en OpenType/CFF (`fonts-adobe-sourcesans3`), que ReportLab no puede incrustar, y no trae Arvo.

## Decisión

1. La apariencia se dibuja con ReportLab, ya dependencia del informe PDF, como un PDF de una página del tamaño del recuadro (`berigna.core.appearance`). pyHanko la coloca como apariencia estática del campo de firma (`StaticStampStyle`).
2. Tipografías: Source Sans 3 (Regular y Semibold) para el texto y Arvo Bold para el nombre del firmante, en TrueType, incluidas en el paquete (`src/berigna/core/fonts/`) con sus licencias SIL OFL 1.1. Origen: Source Sans 3 3.052R del repositorio de Adobe (`adobe-fonts/source-sans`); Arvo del repositorio de Google Fonts (`google/fonts`, `ofl/arvo`). Se incrustan como subconjunto en cada PDF firmado.

   | Archivo | SHA-256 |
   |---|---|
   | `SourceSans3-Regular.ttf` | `4644c81b86ec9caaa76b634889968ed3c4f4f52f054855933acc7c2b21e53b0f` |
   | `SourceSans3-Semibold.ttf` | `a3f4f8dcf343a8f24dc61951de93f3ba1558b15cd250ba24af8a40e957081b7d` |
   | `Arvo-Regular.ttf` | `f41bd41471ec2db7140351bdde614da5341524503598ff7fe79f3c89c13b605e` |
   | `Arvo-Bold.ttf` | `6239b2edee762db0ab99343137c9ba15ae81fc843da2e76a0a395781748cc21f` |

3. Contenido del sello: "Firmado digitalmente por", el nombre del titular (sin el sufijo "FIR 12345678 hard" de los certificados del DNIe), el DNI como lo elija el usuario en Preferencias (`appearance-dni`: los últimos cuatro dígitos, `****1234`, por defecto; completo; o ninguno, decisión del 2026-10-28), la fecha y hora locales con su desfase horario, y el motivo y la ubicación si los hay. Los textos fijos y la fecha siguen el idioma del sello (`appearance-language`, RF-092), con independencia del de la interfaz. Disposición (2026-10-28): en un recuadro más ancho que alto, el QR o la imagen van a la izquierda del texto; en uno más alto que ancho, encima, separados por el filete. La orientación sale de la forma del recuadro que dibuja el usuario, sin otra opción. La lista de apariencias empieza por "No visible".
4. Código QR: los mismos datos del firmante y la fecha, y "Cómo verificar: https://berigna.noggalito.com/verificar". El texto va en UTF-8 precedido del indicador ECI 26, que declara la codificación: sin él, un lector de teléfono leyó "Cómo" como "C髇o". No lleva el nivel de firma, porque el sello se dibuja antes de firmar y un B-LT puede quedar en B-T si los servicios de revocación no responden; tampoco identifica el documento.
5. Color: tinta carbón (`#2B1E20`) y un filete burdeos de la marca; fondo transparente.
6. La rúbrica y el logotipo se cargan una vez en Preferencias y se guardan en `$XDG_DATA_HOME/berigna/apariencia/`, convertidos a PNG (sin metadatos EXIF) y reducidos a 1200 px.
7. El sello se dibuja con los datos del certificado después de validarlo y antes de pedir el PIN: un recuadro demasiado pequeño, una página inexistente o girada, o una imagen ilegible se informan sin gastar un intento (ERR-308).
8. El recuadro se expresa respecto al recuadro de recorte (CropBox) que muestra la vista previa; el núcleo lo traslada a las coordenadas de la página. Las páginas giradas (`/Rotate`) aún no admiten firma visible.

## Alternativas consideradas

- Texto de pyHanko con las tipografías estándar del PDF (Helvetica): no sigue la marca y no se incrusta.
- Empaquetar uharfbuzz para Debian: trabajo de empaquetado que no compensa, ya que ReportLab cubre la necesidad.
- Usar `fonts-adobe-sourcesans3` de Debian: su formato CFF no lo incrusta ReportLab.
- QR con una dirección de verificación por documento: berigna no tiene un servicio en línea que pueda verificarlo, y expondría datos del documento.

## Consecuencias

- El paquete incluye cuatro archivos de tipografías (unos 900 KB) y sus licencias; el `.deb` debe declararlas en `debian/copyright` y lintian puede avisar de tipografías dentro de un paquete que no es de tipografías (Fase 5).
- La vista previa del sello en la interfaz usa datos de muestra ("NOMBRES Y APELLIDOS"); el nombre real se conoce al leer la tarjeta al firmar.
- Pendiente: perfiles de apariencia con nombre (RF-081) y firma visible en páginas giradas.
