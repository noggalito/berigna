# Protocolo de la prueba de usabilidad

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-005 |
| Versión | 0.3.0 |
| Estado | Borrador |
| Fecha | 2026-10-29 |
| Responsable | noggalito |

## 1. Objetivo

Comprobar que personas que no conocen berigna pueden firmar y verificar documentos con su DNIe sin ayuda, en español y en quechua. Es el último criterio de salida de la Fase 3 (revisión de usabilidad con al menos 5 personas) y alimenta RNF-USA.

Preguntas que debe responder:

1. ¿Se entiende qué hacer en cada pantalla sin explicaciones?
2. ¿Se entienden los niveles de firma, los avisos y los errores?
3. ¿Las personas confían en el resultado (firmado, válido, no válido)?
4. ¿La traducción al quechua se entiende? ¿Qué términos confunden?

## 2. Participantes

- Al menos 5 personas, titulares de un DNIe con certificados vigentes y que conozcan su PIN. Quien no conozca su PIN no lo prueba con su DNIe: hace las tareas con la tarjeta simulada (§4).
- Perfiles variados: edad (al menos una persona mayor de 50 años), experiencia con computadoras (al menos una con poca), uso de Linux (al menos una que no lo use).
- Al menos 2 quechuahablantes, que hagan la prueba con la interfaz en quechua.
- No participa nadie que haya trabajado en berigna.
- Con 5 personas aparecen la mayoría de los problemas graves; si se consiguen más, mejor.

## 3. Preparación

### 3.1 Instalar berigna

Mientras no haya paquete `.deb` (Fase 5), berigna se instala desde el código fuente, en un equipo con Debian 13 y GNOME, en una cuenta de usuario creada para la prueba (por ejemplo, `prueba`):

1. Paquetes del sistema (como administrador):

   ```bash
   sudo apt install git gettext python3-venv meson ninja-build blueprint-compiler \
     libglib2.0-bin desktop-file-utils pcscd libccid \
     python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-poppler-0.18 \
     python3-cryptography python3-asn1crypto python3-lxml python3-pyscard \
     python3-pyhanko-certvalidator python3-signxml python3-requests python3-reportlab \
     python3-pil python3-qrcode python3-tzlocal python3-click python3-yaml
   ```

2. Código y entorno (en la cuenta de prueba):

   ```bash
   git clone --branch v0.3.0-rc.1 https://github.com/noggalito/berigna.git ~/berigna
   cd ~/berigna
   python3 -m venv --system-site-packages .venv
   .venv/bin/pip install --no-deps 'pyHanko==0.25.1'
   .venv/bin/pip install --no-deps -e .
   ```

   Todos los participantes prueban la misma versión candidata, `v0.3.0-rc.1`, no la rama `main`, que sigue cambiando con la Fase 4 (BRG-DES-002 §6). Si una corrección obliga a repetir tareas, se anota en el registro con qué versión candidata se hizo cada sesión.
3. Lanzador e icono en el escritorio: `scripts/escritorio.sh`. berigna aparece en la cuadrícula de aplicaciones como "berigna (desarrollo)".
4. Comprobación: conectar el lector con un DNIe, abrir berigna y ejecutar ☰ → Diagnóstico. Todo debe salir en ✓, salvo la autoridad de sellado de tiempo mientras no haya una contratada (DP-02).
5. Al terminar la prueba: `scripts/escritorio.sh quitar` y borrar la cuenta de prueba, con sus documentos y su historial.

### 3.2 Entorno de la sesión

- Equipo preparado como en §3.1, en la sesión del usuario de prueba, sin otras ventanas abiertas.
- Lector de tarjetas conectado; DNIe del participante.
- Carpeta `~/Documentos/prueba` con: `contrato.pdf`, `acta-1.pdf`, `acta-2.pdf`, `acta-3.pdf` (sin firmar) y `convenio-firmado.pdf` (con una firma válida). Ninguno con datos reales de personas.
- Historial vacío; idioma de la interfaz según el participante (Preferencias → General → Idioma).
- Formulario de consentimiento firmado (§6), cronómetro y la hoja de observación (§8).

## 4. Seguridad del PIN

Se aplica el protocolo de pruebas con PIN (BRG-CAL-002):

- El participante escribe su PIN él mismo; nadie lo mira, lo dicta ni lo anota. La persona que conduce la prueba se aparta del teclado.
- Si el participante se equivoca de PIN dos veces, se detiene esa tarea: con el DNIe 2.0 hay cinco intentos, pero no se arriesga el bloqueo.
- Quien prefiera no usar su DNIe hace las tareas con la tarjeta simulada de las pruebas automáticas (PIN `123456`), y se anota.
- No se graba la pantalla mientras se escribe el PIN. Las capturas no muestran el DNI completo ni documentos personales.

## 5. Tareas

Se leen en voz alta, una a una, sin decir dónde está cada cosa. El participante piensa en voz alta. Solo se ayuda si lo pide dos veces o si pasan 5 minutos; esa ayuda se anota.

| N.º | Tarea (lo que se dice) | Éxito | Tiempo orientativo |
|---|---|---|---|
| T1 | "Abra `contrato.pdf` y fírmelo con su DNIe." | `contrato-firmado.pdf` creado | 3 min |
| T2 | "Firme `contrato.pdf` de nuevo, esta vez con la firma visible al pie de la última página, con el motivo 'En señal de conformidad'." | Firma visible en el lugar pedido y con ese motivo | 4 min |
| T3 | "Firme a la vez los tres documentos `acta`." | Tres archivos firmados con un solo PIN | 4 min |
| T4 | "¿Es válida la firma de `convenio-firmado.pdf`? ¿Quién la firmó?" | Responde bien las dos preguntas | 2 min |
| T5 | "Guarde el informe de esa verificación en PDF." | Informe guardado | 2 min |
| T6 | "Quiere comprobar que el lector y su DNIe funcionan bien. Hágalo." | Llega al diagnóstico y lo interpreta | 2 min |
| T7 | "¿Qué documentos ha firmado hoy?" | Llega al historial | 1 min |
| T8 (solo quechua) | "Muestre esta pantalla en español y vuelva al quechua." | Usa "Kastilla simipi qhaway" y Preferencias | 2 min |

Situación provocada (con la tarjeta simulada, nunca con el DNIe real): en T1 se pide escribir un PIN equivocado una vez, para ver si se entiende el aviso de intentos restantes.

## 6. Consentimiento

Texto para leer y firmar antes de empezar. Se ofrece también en quechua; en caso de duda, prevalece el texto en español. Cumple la Ley N.° 29733 de Protección de Datos Personales y su reglamento.

> **La prueba.** Participo voluntariamente en una prueba del programa berigna. Se prueba el programa, no a mí. Puedo dejarla en cualquier momento, sin dar explicaciones. Nadie verá ni anotará mi PIN. Los archivos que firme durante la prueba se borrarán al terminar.
>
> **Mis datos.** Responsable: noggalito (`berigna@noggalito.com`). Se usarán solo para mejorar berigna:
>
> - mi nombre y mi firma en este formulario, que se guarda en papel o en un archivo privado, nunca en el repositorio público;
> - las notas de la sesión y mis respuestas al cuestionario, identificadas solo con un código (P1, P2…);
> - si lo acepto abajo, la grabación de la pantalla y la voz, nunca mientras escribo el PIN.
>
> Mi nombre y mi DNI no aparecerán en los resultados. No se comparten con nadie fuera de noggalito.
>
> **Plazos.** La grabación se borra cuando termine el análisis, como máximo tres meses después de la sesión. Este formulario se conserva hasta el cierre de la Fase 3 y, después, un año como prueba del consentimiento. Las notas con código se conservan sin plazo, porque no me identifican.
>
> **Mis derechos.** Puedo pedir el acceso, la rectificación, la cancelación de mis datos u oponerme a su uso, y retirar este consentimiento, escribiendo a `berigna@noggalito.com`. Si no me atienden, puedo reclamar ante la Autoridad Nacional de Protección de Datos Personales.
>
> ☐ Acepto que se grabe la pantalla y la voz.  ☐ No acepto la grabación.
>
> Nombre: ____________________  Fecha: __________  Firma: ____________________

Antes de la primera sesión, el banco de datos de participantes debe estar inscrito ante la Autoridad Nacional de Protección de Datos Personales (documentación interna, BRG-NOR-001 §2.5). Los formularios firmados no entran en ningún repositorio.

## 7. Cuestionario SUS

Al terminar, el participante responde las 10 frases de la escala de usabilidad SUS (*System Usability Scale*), de 1 (muy en desacuerdo) a 5 (muy de acuerdo):

| N.º | Español | Quechua (sin revisar) |
|---|---|---|
| 1 | Creo que usaría berigna con frecuencia. | berignata sapa kuti llamk'achisaqmansi nispa yuyani. |
| 2 | berigna me pareció innecesariamente complicado. | berignaqa mana necesitasqamanta sasa karqan. |
| 3 | berigna me pareció fácil de usar. | berignaqa llamk'achinapaq facilmi karqan. |
| 4 | Necesitaría ayuda de una persona experta para usar berigna. | berigna llamk'achinaypaqqa yachayniyuq runaq yanapayninta necesitayman. |
| 5 | Las funciones de berigna están bien integradas. | berignaq ruwayninkunaqa allin huñusqam kashan. |
| 6 | berigna me pareció poco coherente. | berignaqa mana allin tupaqmi karqan. |
| 7 | Creo que la mayoría de la gente aprendería a usar berigna rápidamente. | Aswan achka runakunam berignata utqaylla llamk'achiyta yachanqaku. |
| 8 | berigna me pareció muy incómodo de usar. | berignaqa llamk'achinapaq mana allinchu karqan. |
| 9 | Me sentí seguro usando berigna. | berignata llamk'achispa allinpi tarikurqani. |
| 10 | Tuve que aprender muchas cosas antes de poder usar berigna. | berignata llamk'achinaypaq achka imakunatam ñawpaqta yacharqani. |

Puntuación: a las frases impares se resta 1; a 5 se le restan las pares; la suma se multiplica por 2,5 (0 a 100). 68 es la media de referencia.

Preguntas abiertas al final: ¿qué fue lo más difícil? ¿Hubo alguna palabra que no entendió? ¿Firmaría así un documento importante? ¿Por qué?

## 8. Registro de resultados

Una fila por participante y tarea, sin datos personales:

| Participante | Idioma | Tarea | Éxito (sí / con ayuda / no) | Tiempo | Errores | Comentarios y citas |
|---|---|---|---|---|---|---|
| P1 | es_PE | T1 | | | | |

Cada problema encontrado se registra con su gravedad:

| Gravedad | Significado |
|---|---|
| 4, crítica | Impide terminar la tarea o lleva a firmar algo que no se quería |
| 3, grave | Se termina con ayuda o con mucho esfuerzo |
| 2, moderada | Retrasa o confunde, pero se supera |
| 1, menor | Estética o de redacción |

Los problemas de gravedad 3 y 4 se corrigen antes de cerrar la Fase 3; los de 1 y 2 se convierten en incidencias. Las palabras quechuas que confundan se anotan en el glosario (BRG-UX-003) para la revisión de la 1.1.

## 9. Criterio de aceptación

- T1, T3 y T4 completadas sin ayuda por al menos 4 de 5 participantes.
- Ningún problema de gravedad 4 sin corregir.
- SUS medio de al menos 68.
- Ningún participante cree haber firmado cuando no firmó, ni al revés.
