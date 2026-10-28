# ADR-0017: Ayuda contextual en línea, por versión

- Estado: Aceptado
- Fecha: 2026-10-28
- Origen: decisión del titular del 2026-10-28 (sitio berigna.noggalito.com)

## Contexto

Varias opciones de berigna son técnicas (nivel de firma, algoritmo de *hash*, TSA, proxy, lista de confianza) y el usuario necesita entender qué elige en el momento de elegirlo. El proyecto tendrá un sitio propio, `berigna.noggalito.com`, desplegado con una instancia de Odoo, que alojará el proyecto y una ayuda en línea según la versión del programa. Además, RF-091 exige un manual en formato Mallard accesible desde el menú, que es evidencia de la acreditación (ACR-22) y funciona sin conexión.

## Decisión

1. Junto a cada opción técnica, la interfaz muestra un botón "Más información" (`help-about-symbolic`) que abre la página de ayuda de esa opción en el navegador (`berigna.ui.help`).
2. Dirección: `https://berigna.noggalito.com/ayuda/<versión>/<idioma>/<tema>`.
   - `<versión>`: la del programa que se ejecuta, mayor.menor (`1.0`, `1.1`), para que la ayuda describa lo que el usuario ve.
   - `<idioma>`: `es` o `quz`, según el idioma de la interfaz.
   - `<tema>`: un identificador estable en español (`niveles-de-firma`, `algoritmo-de-hash`, `autoridad-de-sellado-de-tiempo`, `tiempo-de-espera`, `proxy`, `lista-de-confianza`). Los temas nuevos se añaden a `HelpTopic`.
3. La dirección solo lleva la versión, el idioma y el tema: ningún dato del usuario ni del documento.
4. La ayuda en línea complementa el manual Mallard de RF-091; no lo sustituye. El manual sigue siendo la referencia sin conexión y la evidencia de la acreditación.
5. Antes de publicar una versión, cada tema de `HelpTopic` debe tener su página en el sitio, en los dos idiomas (lista de comprobación de la versión).

## Alternativas consideradas

- Solo el manual Mallard: no da una explicación junto a la opción, y obliga a buscar.
- Textos largos dentro de la interfaz: alargan las Preferencias y obligan a traducir y revisar más texto en la propia aplicación; la explicación breve se mantiene en los subtítulos.
- Una dirección sin versión: la ayuda dejaría de corresponder a lo que ve quien usa una versión anterior.

## Consecuencias

- Hasta que el sitio exista, los enlaces llevan a páginas inexistentes; no afecta al funcionamiento.
- Recomendación para el sitio: escribir las páginas una sola vez, en Mallard, y publicarlas en Odoo a partir de su exportación HTML (`yelp-build html`), para no mantener dos ayudas que se desincronicen.
- El sitio necesita una página por versión publicada; las versiones antiguas se conservan.
