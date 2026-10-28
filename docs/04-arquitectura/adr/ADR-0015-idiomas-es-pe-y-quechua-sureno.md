# ADR-0015: Idiomas de la v1.0, español del Perú y quechua sureño

- Estado: Aceptado
- Fecha: 2026-10-27
- Origen: DP-14
- Modifica: ADR-0011 (puntos 2, 3 y 5 en lo que se refiere a en_US; los idiomas de la v1.0)

## Contexto

ADR-0011 fijó dos idiomas completos para la v1.0: español del Perú (es_PE) e inglés de Estados Unidos (en_US). El titular cambió el segundo idioma por una lengua originaria del Perú, con el objetivo de llegar al mayor número posible de quechuahablantes, y aplazó en_US a la versión 1.1.

Se evaluaron el kichwa amazónico (variedades de Lamas, `qvs`, y del Napo, `qvo`, con decenas de miles de hablantes) y el quechua sureño (variedades cusco-collao, `quz`, y ayacucho-chanka, `quy`). El quechua sureño es la lengua originaria más hablada del país, con varios millones de hablantes. Tiene un alfabeto oficial y material escrito del Estado, y es la única de estas lenguas para la que Debian trae una configuración regional (`quz_PE`, "Cusco Quechua locale for Peru").

## Decisión

1. Idiomas de la v1.0: es_PE y quechua sureño, ambos completos. La interfaz, las explicaciones de verificación, los informes, el sello visible, el aviso legal y el manual de usuario se traducen.
2. Variedad y escritura del quechua: la configuración regional de referencia es `quz_PE` (cusco-collao). La traducción usa el alfabeto oficial y la norma escrita del quechua sureño, que también leen los hablantes de la variedad ayacucho-chanka. Modificado el 2026-10-28 (DP-14): en la v1.0 la traducción se hace con traductores en línea y ayuda de IA, con un glosario terminológico propio; la corrección por personas hablantes llega en la versión 1.1.
3. Catálogo: `po/quz.po`, que se instala como `quz`, `quy` y `qu`, para que cualquier configuración de quechua sureño lo encuentre.
4. en_US pasa a la versión 1.1. Los textos fuente (`msgid`) siguen escritos en inglés, según la convención de gettext (ADR-0011, punto 2), pero en la v1.0 no son un idioma ofrecido al usuario.
5. Reglas de respaldo, que sustituyen al punto 5 de ADR-0011:
   - las configuraciones de quechua sureño (`quz`, `quy`, `qu`) muestran el catálogo de quechua;
   - cualquier otro idioma, incluidos el español de otros países, el inglés y `C`, muestra es_PE. Para eso el catálogo es_PE es también el de respaldo, y nunca se muestra el texto fuente en inglés.
6. En las preferencias (clave `ui-language`) se elige entre el idioma del sistema, es_PE y quechua. Cada idioma aparece escrito en su propia lengua.
7. Prevalencia legal: se mantiene el punto 3 de ADR-0011. La versión es_PE de los textos con implicaciones legales prevalece y la versión en quechua lo indica expresamente.
8. Formatos regionales: con quechua, fechas y números siguen `quz_PE`. Los informes JSON siguen en ISO 8601 y UTC.

## Alternativas consideradas

- Kichwa amazónico (`qvs`, `qvo`): se descartó porque llega a muchos menos hablantes, carece de configuración regional del sistema y tiene poca terminología escrita.
- Mantener en_US en la v1.0 y añadir quechua: se descartó por decisión del titular, para concentrar el esfuerzo de traducción y revisión.
- Escribir los textos fuente en español: se descartó porque obligaría a reescribir todos los `msgid` al añadir en_US en la 1.1.

## Consecuencias

- La CI exige es_PE y quechua al 100 % (PR-I18N-*). Una cadena nueva no se integra en `main` sin su traducción al quechua o sin una entrada marcada como pendiente de los traductores, que bloquea la versión (riesgo R-19).
- Sin corrección humana hasta la 1.1, un texto crítico puede cambiar de sentido en quechua (riesgo R-19). Se mitiga con el glosario, la traducción cruzada al castellano de los textos críticos, la prevalencia del texto es_PE (punto 7) y un aviso de traducción sin revisar en la interfaz y en el informe PDF en quechua (diseño de interfaz §4.2).
- Las pruebas de usabilidad (RNF-USA-06) incluyen al menos una sesión con participantes quechuahablantes.
- Los lectores de pantalla (Orca y speech-dispatcher) no tienen voz en quechua. La accesibilidad por voz en quechua queda fuera de la v1.0.
- Los textos que hoy están en en_US en los requisitos y en el diseño de la interfaz (ejemplos de explicaciones, tabla de niveles) se reescriben para es_PE y quechua; los de en_US se conservan como referencia para la 1.1.
