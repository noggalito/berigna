# Plan de mantenimiento

| Campo | Valor |
|---|---|
| Documento | BRG-MAN-001 |
| Versión | 0.1.0 |
| Estado | Borrador |
| Fecha | 2026-10-28 |
| Responsable | noggalito |

## 1. Propósito y alcance

Este plan define cómo se mantiene berigna después de publicar la versión 1.0: qué versiones se publican y cuánto tiempo se mantienen, qué hechos externos obligan a publicar, qué se vigila de forma automática, qué se comprueba antes de cada versión y cómo se atienden los fallos de seguridad y las incidencias.

Se aplica al programa, a sus paquetes y a la ayuda en línea. La relación con INDECOPI, RENIEC y los proveedores se lleva en la documentación interna.

## 2. Criterios

1. Una firma que berigna da por válida debe serlo. Un fallo que haga aceptar una firma inválida, o que exponga el PIN, se corrige antes que cualquier otra cosa.
2. Los cambios de confianza (raíces, TSL, algoritmos) se publican aunque el código no cambie, y antes de que el cambio externo entre en vigor.
3. Una versión publicada no cambia de comportamiento sin cambiar de número. Las versiones de corrección no añaden funciones ni cambian la configuración.
4. Cada versión se prueba con un DNIe real y se contrasta con el validador oficial (Firma Perú).
5. El trabajo depende de personas: ninguna credencial ni ningún conocimiento necesario para publicar puede estar en manos de una sola persona.

## 3. Versiones y ramas

Versionado semántico (`MAYOR.MENOR.PARCHE`):

| Tipo | Contenido | Ejemplos |
|---|---|---|
| Parche (1.0.x) | Fallos, seguridad, cambios de confianza, cumplimiento normativo, traducciones corregidas | Nueva raíz de ECERNEP; una CRL que deja de descargarse; un mensaje mal traducido |
| Menor (1.x) | Funciones nuevas compatibles con la configuración y los formatos existentes | Inglés, PIN pad, Flatpak, DNIe 1.0 y 3.0 (versión 1.1) |
| Mayor (x.0) | Cambios incompatibles en la configuración, los perfiles o los formatos de informe, o el fin del soporte de una versión de Debian | Paso a Debian 14 si obliga a abandonar Debian 13 |

Ramas:

- `main`: desarrollo de la siguiente versión menor.
- `estable/1.0`, `estable/1.1`…: se crean al publicar cada versión menor y solo reciben correcciones, que se hacen primero en `main` y se trasladan con `git cherry-pick -x`.
- Cada versión se marca con una etiqueta firmada (`v1.0.0`).

Soporte:

- Se mantiene la última versión menor. La anterior recibe correcciones de seguridad y de confianza durante 3 meses después de publicar la siguiente.
- El fin del soporte de una versión se anuncia con al menos un mes de antelación en las notas de versión y en el sitio.
- Debian 13 se mantiene mientras tenga soporte de seguridad de Debian (hasta mediados de 2028; LTS hasta 2030). La compatibilidad con Debian 14 se prepara desde que entre en congelación.

## 4. Hechos externos que obligan a publicar

| Origen | Señal | Acción | Plazo |
|---|---|---|---|
| RENIEC / ECERNEP | Raíz o CA nueva, cambio de las direcciones OCSP o CRL, certificados de otro perfil | Actualizar el almacén de confianza o `core.net`; prueba HIL | Versión de parche antes de que se emitan certificados con la cadena nueva |
| RENIEC | DNIe nuevo o *applet* distinto | Investigación (como SPK-06) y driver | Versión menor |
| INDECOPI | Rotación del certificado que firma la TSL (su raíz está fijada en el paquete, ADR-0014) o cambio de formato de la TSL | Nueva raíz fijada; prueba con la TSL real | Versión de parche **antes** de la rotación |
| INDECOPI | Cambios en la guía de acreditación o en la lista de TSA acreditadas | Revisar requisitos y DP-02 | Según el caso |
| Normativa | Ley 27269, su reglamento, normas de la Secretaría de Gobierno y Transformación Digital | Revisar requisitos y textos legales | Según la entrada en vigor |
| ETSI | Revisión de EN 319 102-1, EN 319 142 o TS 119 312 (algoritmos y tamaños de clave) | Ajustar la validación y los algoritmos admitidos | Versión menor; de parche si un algoritmo pasa a inseguro |
| Firma Perú | Nueva versión del validador (hoy Firma Perú 1.1.0 con DSS 5.11.1) | Repetir la matriz de interoperabilidad | En el siguiente ciclo de versión |
| Debian | Actualización de seguridad de una dependencia, versión nueva de Debian | Probar contra *stable* y *testing* (§5) | Versión de parche si algo se rompe |
| Dependencias | Versión nueva de pyHanko, pyhanko-certvalidator, cryptography, pyscard, GTK o libadwaita | Revisar el registro de cambios; actualizar el paquete de pyHanko propio (ADR-0013) | Versión menor, salvo seguridad |

Quién vigila cada origen se asigna en la documentación interna.

## 5. Vigilancia automática

| Comprobación | Frecuencia | Qué detecta |
|---|---|---|
| CI de cada PR (`scripts/verificar.sh` en Debian 13, con Xvfb) | Cada cambio | Formato, tipos, pruebas y cobertura |
| CI programada contra Debian *stable* y *testing* | Semanal | Roturas por actualizaciones de Debian antes de que lleguen a los usuarios |
| Descarga y verificación de la TSL real de INDECOPI | Semanal | Rotación del firmante, cambio de formato, lista caducada |
| Respuesta de los OCSP y de las CRL de RENIEC y de la TSA configurada | Semanal | Direcciones cambiadas o servicios caídos (R-17) |
| `pip-audit` sobre el entorno de desarrollo y `debsecan` sobre el contenedor | Semanal | Vulnerabilidades conocidas en las dependencias |
| Dependabot para las *actions* de GitHub | Mensual | *Actions* desactualizadas |

Las comprobaciones de red no bloquean la CI de los PR: abren una incidencia cuando fallan. Ninguna comprobación automática usa un DNIe real ni un PIN.

## 6. Proceso de cada versión

Antes de etiquetar:

1. Congelación de cadenas dos semanas antes, para que se pueda traducir al quechua (ADR-0015).
2. `scripts/verificar.sh` y la CI en verde.
3. Pruebas HIL sin PIN (`BERIGNA_HIL=1 pytest -m hil`) con al menos dos lectores.
4. Pruebas con el PIN real según el [protocolo](../07-calidad/protocolo-pruebas-con-pin.md): un PDF por nivel disponible y por apariencia de la firma visible.
5. Validación de esos PDF en el validador de Firma Perú; resultado archivado en la bitácora de pruebas con PIN (sin datos personales en el repositorio).
6. Paquetes: compilación reproducible, `lintian --pedantic`, `appstreamcli validate` y `desktop-file-validate` sin errores.
7. `CHANGELOG.md` con la versión y la fecha; notas de versión en es_PE y en quechua.
8. Ayuda en línea publicada para la `mayor.menor` nueva (ADR-0017). La de versiones anteriores no se retira.

Al publicar: etiqueta firmada, paquetes firmados en el repositorio APT, anuncio en el sitio y apertura de la rama `estable/` si es una versión menor.

## 7. Seguridad

- `SECURITY.md` en la raíz del repositorio con el canal privado de aviso: los avisos de seguridad privados de GitHub y `berigna@noggalito.com`. El sitio publica `https://berigna.noggalito.com/.well-known/security.txt` (RFC 9116) con los mismos datos.
- Acuse de recibo en 5 días hábiles.
- Plazos de corrección:

  | Gravedad | Ejemplos | Plazo |
  |---|---|---|
  | Crítica | Firma inválida dada por válida; PIN expuesto o enviado sin confirmación; ejecución de código al abrir un archivo | 7 días |
  | Alta | Denegación de servicio con un archivo; datos personales en registros | 30 días |
  | Media y baja | Endurecimiento, mensajes engañosos | Siguiente versión menor |

- Cada corrección de seguridad lleva un aviso publicado y, si procede, un CVE solicitado a través de GitHub.
- Las vulnerabilidades de pyHanko u otras dependencias se avisan a su proyecto antes de publicarlas.

## 8. Incidencias y soporte

- Plantillas de incidencia (fallo, propuesta, problema con un lector o un DNIe) que piden la versión, el lector y el informe de diagnóstico (RF-082), y advierten que no se adjunten PDF firmados ni capturas con el DNI completo.
- Clasificación semanal con etiquetas de tipo, componente y prioridad.
- Objetivo de primera respuesta: 5 días hábiles.
- berigna no tiene telemetría: las incidencias y las pruebas con usuarios son la única fuente de datos de uso.

## 9. Traducciones y ayuda

- es_PE es el texto que prevalece (ADR-0011): toda cadena nueva se traduce al es_PE en el mismo PR.
- El quechua se traduce durante la congelación de cadenas; desde la versión 1.1, con revisión de personas (DP-14).
- La ayuda en línea tiene una versión por `mayor.menor` y por idioma (ADR-0017).

## 10. Continuidad

- Al menos dos personas mantenedoras con permisos para fusionar y publicar.
- Inventario de credenciales en la documentación interna: clave de firma del repositorio APT, claves de firma de los commits, organización de GitHub, dominio `noggalito.com` y sitio. Cada una con dos personas con acceso, fecha de caducidad y procedimiento de rotación.
- La clave de firma del repositorio APT caduca y se renueva cada dos años; la nueva se publica con antelación en el paquete de claves.
- El titular del proyecto es la persona jurídica noggalito (DP-05): responde ante INDECOPI y firma las versiones. El contacto único es `berigna@noggalito.com`.

## 11. Indicadores

Se revisan en cada versión menor:

- Tiempo desde un hecho externo (§4) hasta la versión que lo resuelve.
- Tiempo de corrección de las incidencias de seguridad frente a los plazos de §7.
- Incidencias abiertas por prioridad y antigüedad.
- Cobertura de pruebas (2026-10-29: núcleo al 100 %, total al 95 %).
- Resultados de la matriz con Firma Perú.

## 12. Pendiente para aplicar este plan

- Plantillas de incidencia y `security.txt` en el sitio.
- Activar los avisos de seguridad privados en GitHub (Settings → Code security).
- CI programada contra *stable* y *testing*, y comprobaciones semanales de la TSL y de los servicios de RENIEC.
- Inventario de credenciales y segunda persona mantenedora (documentación interna).
- Política de rotación de la clave del repositorio APT, cuando exista (Fase 5).
