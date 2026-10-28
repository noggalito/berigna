# ADR-0016: Previsualización de PDF con Poppler

- Estado: Aceptado
- Fecha: 2026-10-28
- Origen: arquitectura general §6 (decisión pendiente de la Fase 3)

## Contexto

La interfaz muestra el documento antes de firmarlo (WYSIWYS, P-01, RF-018). Hay dos opciones en Python: Poppler-GLib, por GObject Introspection, y pypdfium2, el motor de PDF de Chromium.

## Decisión

1. La previsualización de la v1.0 usa Poppler-GLib (`gir1.2-poppler-0.18`), dibujada con Cairo en la interfaz (`berigna.ui.preview`).
2. Poppler solo dibuja: lo que se firma son los bytes que leyó el núcleo, cuyo SHA-256 se comprueba antes del PIN y justo antes de firmar (RF-018). Poppler no interviene en la firma ni en la verificación.
3. La previsualización queda aislada en un módulo, para poder cambiar de motor en versiones posteriores (pypdfium2 u otro) sin tocar el resto de la interfaz.

## Alternativas consideradas

- pypdfium2: mejor fidelidad con algunos PDF, pero no está empaquetado en Debian 13 y añadiría un binario de PDFium que mantener (ADR-0013). Queda como opción futura, por ejemplo en el Flatpak de la versión 1.1.

## Consecuencias

- Dependencia nueva del paquete: `gir1.2-poppler-0.18`, también en la CI.
- Un PDF que Poppler no puede dibujar se puede firmar igualmente si el núcleo lo lee; la interfaz avisa de que no hay vista previa.
