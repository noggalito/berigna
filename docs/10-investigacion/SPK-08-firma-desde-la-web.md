# SPK-08: Firma desde la web

| Campo | Valor |
|---|---|
| Documento | BRG-INV-008 |
| Versión | 0.2.0 |
| Estado | Pendiente |
| Fecha | 2026-11-10 |
| Responsable | noggalito |

## 1. Contexto

El titular decidió (2026-11-02) adelantar a la versión 1.1 la firma desde la web, que la hoja de ruta tenía como "invocador web" después de la 1.1 (ADR-0002). El núcleo `berigna.core` no depende de la interfaz y ya está preparado para recibir peticiones de otra vía (BRG-ARQ-001 §1).

Una página web no puede leer el DNIe: los navegadores no dan acceso al lector, y la única API que lo haría (Web Smart Card, del WICG) está pensada para aplicaciones aisladas instaladas, no para portales públicos. Siempre hace falta un programa local, y ese programa es berigna.

## 2. Líneas de trabajo

| # | Línea | Qué es |
|---|---|---|
| 1 | Verificador web | Una página donde se sube un documento firmado y se ve si la firma es válida, con el mismo núcleo de verificación. No necesita DNIe ni lector |
| 2 | Invocador | Una página web pide a berigna que firme un documento: berigna lo descarga, lo muestra, pide el PIN, firma y sube el resultado |
| 3 | Compatibilidad | berigna entiende los parámetros que ya envían los sistemas integrados con el firmador web de Firma Perú, con nombre propio |

## 3. Opción que se evalúa para el invocador

Extensión del navegador con *native messaging* y "documento completo":

1. Una biblioteca JavaScript que la página incrusta llama a `berigna.firmar({ documento, destino, formato, nivel })`, con URL de un solo uso que emite el servidor.
2. La extensión, mínima, solo pasa mensajes y añade el origen de la página, que pone el navegador y la página no puede falsificar.
3. El navegador lanza un puente nativo por cada petición. El puente valida la petición (HTTPS, mismo dominio que la página, tamaño razonable) y la entrega a berigna, por D-Bus si ya está abierta.
4. berigna descarga el documento, muestra qué sitio pide la firma y qué documento, pide el PIN, firma con el núcleo actual y sube el resultado al destino. La página recibe solo un estado: firmado, nivel alcanzado e identificador.

berigna descarga y sube el documento porque el navegador limita a 1 MB lo que el programa nativo devuelve a la extensión, y un PDF firmado no cabe.

Se descarta un servidor en `localhost`: desde Chrome 142 una página que lo llama dispara un aviso de acceso a la red local, un puerto abierto recibe peticiones de cualquier pestaña, y un proceso de larga vida mantendría la tarjeta autenticada (CS-01). También se descarta firmar "solo la huella" sin mostrar el documento, salvo que berigna reciba además el documento y recalcule la huella: firmar sin ver lo firmado rompe RF-018 y los controles de AM-02 y AM-03.

## 4. Sin lector de tarjetas: el teléfono como puente

Quien no tenga lector puede usar el NFC de su teléfono como puente hacia berigna en el escritorio (SPK-07, opción C). Las dos piezas se combinan sin depender una de otra: la extensión y el puente nativo hablan con berigna, y berigna habla con la tarjeta por PC/SC o, sin lector, por el teléfono emparejado. El flujo de §3 no cambia, y las condiciones de seguridad de SPK-07 §4 (el PIN no cruza el teléfono en claro, lista blanca de APDU en los dos extremos, emparejamiento autenticado) se aplican igual.

## 5. Preguntas

1. ¿Se puede limitar la extensión a los sitios que el usuario autoriza, la primera vez y de forma revocable, en Chrome y en Firefox, sin pedir "leer y cambiar datos en todos los sitios"?
2. ¿Cómo coordina el puente nativo con una instancia de berigna ya abierta (D-Bus), y qué ve el usuario si la tarjeta está ocupada por otra firma?
3. ¿Qué pasa con los navegadores en Snap o Flatpak, donde *native messaging* necesita un portal? En Debian, Firefox ESR y Chromium son `.deb`.
4. ¿Qué variante de `core.signing` firma desde bytes, sin rutas en disco, conservando el orden de seguridad (archivo sin cambios, certificado y TSA antes del PIN, RF-006, RF-018)?
5. ¿Qué parte de los parámetros del firmador web de Firma Perú hace falta para la compatibilidad, y cómo se presenta sin confundirse con Firma Perú?
6. Con el teléfono como puente (§4): ¿cuánto añade a la firma web, y cómo se informa del progreso si la tarjeta se mueve?

## 6. Seguridad

Antes del código, el modelo de amenazas (BRG-SEG-001) se amplía con:

- Un sitio malicioso o de nombre parecido que dispara firmas: el dominio se muestra en grande, la autorización es por sitio y revocable, y el PIN se pide siempre en berigna.
- Uso de berigna para leer la red interna o enviar documentos a terceros (SSRF): solo HTTPS, mismo dominio que la página que pide, sin redirecciones a otros dominios.
- Lotes masivos pedidos desde la web: límite y confirmación explícita.
- Una actualización maliciosa de la extensión: la extensión no decide nada; berigna valida cada petición.
- Una sesión de la tarjeta que queda abierta: una petición, una sesión, cerrada al terminar (CS-01).

## 7. Método

Un *spike* de una semana con un prototipo mínimo: una página de prueba, la extensión para Chromium y Firefox, el puente nativo y un diálogo de berigna que muestra el origen y el documento, con la tarjeta simulada (sin PIN real). Responde las preguntas 1 a 3 y deja escritos el ADR del invocador y la ampliación del modelo de amenazas.

## 8. Criterio de cierre

- Respuestas a las preguntas de §5, con la matriz de navegadores y sistemas que se soportan.
- El ADR del invocador web y la ampliación de BRG-SEG-001.
- Una estimación del MVP (PAdES, un documento por petición) y de la versión completa (lotes, CAdES y XAdES, compatibilidad).
- Las implicaciones para la acreditación de la extensión y el puente, que no hacen criptografía, pendientes de consultar a INDECOPI junto con las de SPK-07.

## Fuentes

- [Native messaging, Chrome for Developers](https://developer.chrome.com/docs/extensions/nativeMessaging)
- [Local Network Access, Chrome for Developers](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access)
- [Web eID: extensión del navegador (MIT)](https://github.com/web-eid/web-eid-webextension)
- [Web Smart Card API (WICG)](https://github.com/WICG/web-smart-card/)
- [Componente web de Firma Perú (PCM)](https://resources.firmaperu.gob.pe/documentos/firmador-componente-web.pdf)
- Guía para el uso e integración de la Plataforma Nacional de Firma Digital (R.S. 002-2022-PCM/SGTD), a la que remite la PCM para la integración con Firma Perú (carta D000001-2026-PCM-SSPRD, 2026-11-09)
- [Native messaging en el Firefox Snap (Ubuntu)](https://discourse.ubuntu.com/t/call-for-testing-native-messaging-support-in-the-firefox-snap/29759)
