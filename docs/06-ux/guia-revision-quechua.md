# Guía para revisar la traducción al quechua

| Campo | Valor |
|---|---|
| Documento | BRG-UX-004 |
| Versión | 0.1.0 |
| Estado | Borrador |
| Fecha | 2026-11-07 |
| Responsable | noggalito |

## 1. Propósito y alcance

Cómo puede una persona que habla quechua sureño revisar y corregir la traducción de berigna, aunque no programe. La primera traducción (2026-10-29) es automática y no está revisada por hablantes (DP-14, ADR-0015); la corrección por personas está prevista para la versión 1.1 (RNF-USA-09). Mientras tanto la interfaz y el informe PDF en quechua lo avisan y el texto en español prevalece (BRG-UX-001 §4.2).

Se revisan dos cosas, en este orden:

1. El glosario terminológico (BRG-UX-003, `docs/06-ux/glosario-quechua.md`): los términos fijos que se repiten en toda la interfaz.
2. El catálogo `po/quz.po`: todos los textos del programa, de la entrada de escritorio y de la ficha de la tienda de aplicaciones (metainfo).

Una corrección de un término cambia primero el glosario y después todas las entradas del catálogo que lo usan, para que el mismo concepto se diga siempre igual (BRG-UX-003 §4).

## 2. Qué textos importan más

RNF-USA-09 pide revisión humana sobre todo de los textos que pueden cambiar una decisión del usuario o el sentido legal de un resultado. Si el tiempo es poco, conviene empezar por ellos:

| Prioridad | Textos | Dónde aparecen en `po/quz.po` (líneas `#:`) |
|---|---|---|
| 1 | Diálogo del PIN y avisos de intentos y de bloqueo del DNIe | `src/berigna/ui/signing.py` |
| 1 | Resultados de la verificación y sus explicaciones (válida, no válida, indeterminada) | `src/berigna/core/report/`, `src/berigna/ui/verification.py` |
| 1 | Aviso de traducción sin revisar | `data/ui/window.blp`, `src/berigna/ui/window.py` |
| 2 | Mensajes de error (ERR-xxx) y del diagnóstico | `src/berigna/core/errors.py`, `src/berigna/ui/diagnostics.py` |
| 3 | Menús, preferencias, historial, lotes | resto de `src/berigna/ui/` |
| 3 | Entrada de escritorio y ficha de la tienda | `data/` |

## 3. Cómo se lee el catálogo

Cada entrada de `po/quz.po` tiene esta forma:

```po
#: src/berigna/core/report/messages.py:140
#, python-brace-format
msgid "Signed by {name}."
msgstr "{name} firmarqan."
```

- `#:` dice en qué archivo del programa está el texto. No se cambia.
- `#.` (cuando existe) es una nota para quien traduce: explica el contexto. No se cambia.
- `msgid` es el texto fuente, en inglés, como lo exige gettext. No se cambia. El español de referencia está en la misma entrada de `po/es_PE.po`, que es el texto que prevalece.
- `msgstr` es la traducción al quechua. Es lo único que se corrige.

Las herramientas de traducción como Poedit o Gtranslator (paquete `gtranslator` de Debian) muestran las entradas una por una y comprueban el formato al guardar. Cualquier editor de texto sirve también.

## 4. Reglas

Las reglas de lengua son las del glosario (BRG-UX-003 §2); aquí se resumen y se añaden las del formato del catálogo.

| Regla | Detalle | Ejemplo |
|---|---|---|
| Variedad | Quechua sureño de Cusco-Collao (`quz`), alfabeto oficial de tres vocales | |
| Tratamiento | Segunda persona e imperativo simple, como el tuteo del español de la interfaz | *Qillqata kichay* ("Abre un documento") |
| Plural | Una sola forma: el sustantivo no cambia tras un número (`nplurals=1`). Las entradas con `msgid_plural` llevan solo `msgstr[0]` | *kimsa qillqa* |
| Préstamos | Los términos técnicos sin equivalente asentado se toman del español y llevan sufijos quechuas | *firmay*, *certificadoyki*, *PINqa* |
| Lo que no se traduce | berigna, DNI, DNIe, PIN, PDF, CSV, JSON, QR, SHA-256, TSA, OCSP, RENIEC, INDECOPI, IOFE, Firma Perú, Ciudadano Digital, los niveles (B-B a B-LTA), los códigos ERR-xxx y ETSI, y los comandos | `sudo apt install pcscd` queda igual |
| Marcadores | Lo que va entre llaves (`{name}`, `{level}`, `{count}`…) se copia tal cual, sin traducir la palabra de dentro. Sí puede cambiar de sitio dentro de la frase, para respetar el orden del quechua | `Signed by {name}.` → *{name} firmarqan.* |
| Teclas de acceso | El guion bajo marca la letra que se activa con Alt. Debe quedar uno solo por texto, delante de una letra de la propia traducción, y sin repetir letra entre los elementos de un mismo menú | `_Preferences` → *_Akllanakuna* |
| Nombre del programa | Siempre en minúscula, también con sufijos | *berignaqa*, *berignawan* |
| Puntuación y saltos | Se conservan los `\n`, los puntos suspensivos (`…`) y el punto final cuando el texto fuente los tiene | |

Si una entrada no se sabe traducir con seguridad, se deja la traducción automática como está y se explica la duda en el envío (§6). Una entrada vacía o marcada `#, fuzzy` impide publicar una versión (BRG-DES-001 §3), así que no se vacían entradas.

## 5. Cómo probar la traducción

Con el código fuente en Debian 13 y el entorno de desarrollo preparado (BRG-DES-001 §2):

```sh
msgfmt --check --output-file=/dev/null po/quz.po   # formato y marcadores
scripts/traducciones.sh estado                       # entradas traducidas, dudosas y vacías
scripts/ejecutar.sh                                  # abre berigna con los catálogos recién compilados
```

En berigna: menú principal → Preferencias → General → Idioma de la interfaz → *Runasimi (quechua)*. El cambio es inmediato. La mayoría de las pantallas se recorren sin DNIe: abrir un PDF, verificarlo, las preferencias, el historial y el diagnóstico. El diálogo del PIN solo aparece con un DNIe en el lector; esos textos se revisan en el catálogo, y quien mantiene berigna puede enviar capturas sin datos personales.

Sin entorno de desarrollo, con el paquete instalado, el idioma se elige igual desde Preferencias. Los cambios del catálogo solo se ven tras compilarlo, así que en ese caso basta con `msgfmt --check` y la persona que mantiene berigna prueba el resultado.

## 6. Cómo enviar las correcciones

Por una de estas dos vías:

1. Pull request en GitHub (`https://github.com/noggalito/berigna`), según la [guía de contribución](../../CONTRIBUTING.md): una rama `fix/quechua-…`, commits con `git commit -s` y, si cambia un término, el glosario y el catálogo en el mismo PR. En la descripción: qué partes se revisaron (§2), qué términos cambian y por qué, y las dudas.
2. Correo a `berigna@noggalito.com`, con el asunto "Revisión del quechua" y el archivo `po/quz.po` corregido, o la lista de correcciones (texto en inglés o español, traducción actual, traducción propuesta). No hace falta saber usar git.

En ninguno de los dos casos se envían capturas con datos personales: nombres o números de DNI de un certificado real, ni documentos firmados con un DNIe (guía de contribución, "Datos personales y PIN").

## 7. Qué pasa después

1. La persona que mantiene berigna revisa la parte técnica: formato, marcadores, teclas de acceso, que la interfaz no se corte con los textos nuevos.
2. Si cambia un término, actualiza el glosario y todas las entradas que lo usan.
3. La corrección entra en la siguiente versión y el nombre de quien la hizo, si así lo desea, se añade a los créditos de traducción: la cabecera de `po/quz.po` y la ventana "Acerca de".
4. El aviso de traducción sin revisar (BRG-UX-001 §4.2) se retira solo cuando todo el catálogo, empezando por los textos de prioridad 1, esté revisado por hablantes (RNF-USA-09). Para la versión 1.1 se prevé además la revisión por traductores del Registro Nacional de Intérpretes y Traductores de Lenguas Indígenas u Originarias del Ministerio de Cultura (BRG-UX-003 §4).
