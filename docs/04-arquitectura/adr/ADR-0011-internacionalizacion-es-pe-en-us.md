# ADR-0011: Internacionalización con dos idiomas, es_PE y en_US

- Estado: Aceptado; modificado por [ADR-0015](ADR-0015-idiomas-es-pe-y-quechua-sureno.md). Los idiomas de la v1.0 son es_PE y quechua sureño; en_US pasa a la versión 1.1, y los idiomas no soportados muestran es_PE.
- Fecha: 2026-10-27
- Origen: DP-07

## Contexto

El titular decidió que la v1.0 se publique en español del Perú (es_PE) y en inglés de Estados Unidos (en_US), ambos completos. Hay que definir cómo se implementa la traducción, en qué idioma se escribe el texto fuente y qué ocurre con los entornos que no usan ninguno de los dos idiomas.

## Decisión

1. Mecanismo: GNU gettext para todas las cadenas, tanto en Python (`gettext` / `_()`) como en las vistas Blueprint (`_("…")`), el esquema de GSettings, el archivo `.desktop`, la metainfo de AppStream y la extensión de Nautilus. El manual Mallard se traduce con itstool.
2. Idioma fuente: los `msgid` se escriben en inglés (en_US). Es la convención de GNOME y de gettext, y garantiza un texto legible cuando no hay catálogo instalado. La traducción es_PE se mantiene en `po/es_PE.po`.
3. Fuente de verdad legal: en los textos con implicaciones legales (aviso legal, política de privacidad y explicaciones de los resultados de verificación) prevalece la versión es_PE. La versión en_US es una traducción de cortesía, y esto se indica en el propio texto.
4. Selección del idioma: por defecto se sigue la configuración regional del sistema (`LANGUAGE` / `LC_MESSAGES`). En las preferencias se puede forzar es_PE o en_US (clave `ui-language`), y el cambio se aplica al reiniciar la aplicación.
5. Reglas de respaldo:
   - Cualquier variante del español (es_ES, es_MX, etc.) muestra es_PE. Para eso el catálogo se instala también como `es`.
   - Cualquier otro idioma muestra en_US, que es el texto fuente.
6. Formatos regionales: las fechas, las horas y los números se formatean según la configuración regional activa. Las horas de firma se muestran en la zona horaria local del usuario e indican su desfase respecto de UTC. Los informes JSON siempre usan ISO 8601 en UTC.
7. Separación entre núcleo y presentación: `berigna.core` devuelve resultados estructurados con códigos (`ERR-xxx`, indicaciones ETSI, códigos de explicación) y no frases ya traducidas. La traducción se hace en `ui` y en `core.report`. El núcleo usa gettext solo para los textos que van dentro de documentos generados, como el texto de la firma visible o el informe PDF.
8. Texto de la firma visible: el idioma de la plantilla del sello visible es independiente del idioma de la interfaz y se elige en el perfil de apariencia, con es_PE por defecto. Un documento firmado en Perú normalmente debe llevar el sello en español aunque la interfaz esté en inglés.

## Alternativas consideradas

- Texto fuente en español: se descartó porque obliga a mantener un catálogo en_US para cualquier respaldo y se aleja de la convención del ecosistema.
- Solo es_PE en la v1: se descartó por decisión del titular.

## Consecuencias

- La CI comprueba que ambos catálogos estén al 100 % y que ningún texto quede sin marcar (PR-I18N-*).
- Hay que diseñar la interfaz para textos de longitud variable (pseudolocalización en las pruebas).
- Cada texto nuevo exige su traducción antes de integrarse en `main`.
- El informe de verificación exportado se genera en el idioma que elija el usuario. Por defecto es el de la interfaz.
