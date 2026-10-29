# Protocolo de pruebas con PIN real

| Campo | Valor |
|---|---|
| Documento | BRG-CAL-002 |
| Versión | 0.1.0 |
| Estado | Vigente |
| Fecha | 2026-10-27 |
| Responsable | noggalito |

## 1. Por qué existe

El PIN del DNIe se bloquea tras un número determinado de intentos fallidos consecutivos. Un DNIe bloqueado no puede firmar hasta que su titular haga el trámite de desbloqueo ante RENIEC. `[VERIFICAR]` el número exacto de intentos y el procedimiento de desbloqueo (consulta CE-07 a RENIEC). No debe averiguarse provocando fallos.

Por eso, toda prueba que envíe el PIN de un DNIe real (pruebas HIL, *spikes*, validaciones de interoperabilidad) sigue este protocolo sin excepciones.

## 2. Reglas

| Regla | Detalle |
|---|---|
| PIN-01 | El PIN solo lo teclea su titular, en su propia terminal o en la interfaz de berigna. Nunca se escribe en un archivo, en una variable de entorno, en un argumento de la línea de comandos, en el historial de la shell ni en un chat |
| PIN-02 | Cada ejecución envía el PIN como máximo una vez. Los *scripts* no tienen bucles de reintento |
| PIN-03 | Antes de enviar el PIN se pide una confirmación explícita (`[s/N]`). La respuesta por defecto es no enviar nada |
| PIN-04 | Si el VERIFY no devuelve `9000`, la ejecución se detiene y muestra el código. `63Cx` indica que quedan x intentos |
| PIN-05 | Si quedan 2 intentos o menos, se suspenden todas las pruebas con ese DNIe hasta que el titular confirme el PIN correcto por otra vía (por ejemplo, firmando con ReFirma). Un intento acertado devuelve el contador al máximo |
| PIN-06 | Ante cualquier duda sobre el PIN, se responde `N` a la confirmación. Cancelar no cuesta nada; fallar consume un intento |
| PIN-07 | Prohibido probar a propósito un PIN incorrecto en un DNIe real. Los casos de PIN incorrecto, PIN bloqueado y "último intento" solo se prueban con el simulador o con SoftHSM |
| PIN-08 | Prohibido usar PIN en la CI. Las pruebas automáticas solo usan el simulador o SoftHSM |
| PIN-09 | Cada *script* que use PIN pasa una revisión previa: lista blanca de instrucciones (SELECT, READ BINARY, VERIFY, MSE:SET, PSO:CDS), un solo VERIFY y cierre de la sesión apagando la tarjeta (`SCARD_UNPOWER_CARD`) |
| PIN-10 | Primero se prueba el *script* sin PIN (respondiendo `N`), para comprobar que detecta la tarjeta y lee el certificado correctamente |
| PIN-11 | Solo se envía el PIN de firma (referencia 0x81). No se envían otros PIN del DNIe salvo que una prueba lo requiera de forma expresa y aprobada |
| PIN-12 | Cada envío de PIN se anota en la bitácora (§3), sin el PIN |

## 3. Bitácora de envíos de PIN

Cada envío de PIN con un DNIe real se registra, sin el PIN, en una bitácora interna del proyecto (no publicada), con la fecha, el alias del DNIe, el lector, el *script*, el resultado del VERIFY y los intentos restantes conocidos.

## 4. Si el PIN se bloquea

1. Detener todas las pruebas con ese DNIe.
2. Registrar el incidente en la bitácora.
3. El titular hace el trámite de desbloqueo ante RENIEC (`[VERIFICAR]` canal y requisitos: consulta CE-07).
4. Analizar la causa. Si se debió a un *script* o a berigna, abrir una incidencia de severidad alta (riesgo R-08).
