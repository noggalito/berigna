# Plan de mantenimiento

| Campo | Valor |
|---|---|
| Documento | BRG-MAN-001 |
| Versión | 0.4.1 |
| Estado | Borrador |
| Fecha | 2026-11-08 |
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
| CI de cada PR (`scripts/verificar.sh` en Debian 13, con Xvfb), lista de componentes (SBOM) y medidas de rendimiento | Cada cambio | Formato, tipos, pruebas y cobertura; los componentes y sus licencias; un empeoramiento de más del 50 % (aviso) |
| CI programada contra Debian *stable* y *testing* | Semanal | Roturas por actualizaciones de Debian antes de que lleguen a los usuarios |
| El mismo `.deb` de Debian 13 instalado en Ubuntu 26.04 LTS con sus actualizaciones (*resolute-updates* y *resolute-security*), con la suite contra el paquete instalado (ADR-0023) | Semanal y en cada PR | Roturas y avisos de obsolescencia por actualizaciones de Ubuntu; la CI de cada PR comprueba además que `apt` rechaza el paquete en Ubuntu 24.04 |
| Descarga y verificación de la TSL real de INDECOPI | Semanal | Rotación del firmante, cambio de formato, lista caducada o a menos de 7 días de su NextUpdate |
| Respuesta del OCSP de RENIEC y de cada espejo de las ARL de las CA del almacén | Semanal | Direcciones cambiadas, listas vencidas o servicios caídos (R-17) |
| OSV para lo que no viene de Debian (hoy solo pyHanko) y `debsecan` sobre los paquetes de Debian del SBOM | Semanal | Vulnerabilidades conocidas en las dependencias; `debsecan`, solo informativo |
| Instalación desde el repositorio APT publicado (`https://noggalito.com/apps/deb/`), como un usuario nuevo y a través de la CDN, en Debian 13 y Ubuntu 26.04 (`scripts/vigilar-repositorio.sh`) | Semanal | Firma rechazada o vencida, desafíos de la CDN a `apt`, servidor caído, una versión de GitHub sin publicar en el repositorio, o la subclave de firma a menos de 90 días de caducar |
| Suite completa con la última pyHanko de PyPI | Semanal | Cuánto costará salir de pyHanko 0.25.1 (R-15); nunca abre una incidencia |
| Dependabot para las *actions* de GitHub | Mensual | *Actions* desactualizadas |

Todo está en `.github/workflows/vigilancia.yml` (los lunes) y en la CI de cada PR, con los *scripts* de `scripts/` (BRG-DES-001 §5). Las comprobaciones semanales no bloquean la CI de los PR: abren una incidencia cuando fallan, o comentan en la que siga abierta. Ninguna comprobación automática usa un DNIe real ni un PIN.

No se usa `pip-audit`: compara versiones de PyPI, y Debian corrige sin cambiar la versión de origen, así que daría falsos positivos en los paquetes de Debian (R-DES-02). La TSA configurada se comprobará cuando haya una de producción (DP-02).

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

Al publicar: etiqueta firmada, paquetes firmados en el repositorio APT, anuncio en el sitio y apertura de la rama `estable/` si es una versión menor. El repositorio APT (BRG-DSP-001 §4), en la estación del titular, la única con la subclave de firma:

1. Una carpeta con los `.deb` de la versión de GitHub y su `SHA256SUMS` (más `noggalito-archive-keyring` si cambió, con su línea añadida al `SHA256SUMS`).
2. `SERVIDOR=<alias ssh> scripts/publicar-repositorio.sh <carpeta>`: comprueba las sumas, arma, firma (pide la frase de la subclave), sube y comprueba a través de la CDN.
3. Instalación desde cero en contenedores limpios de Debian 13 y Ubuntu 26.04 con las instrucciones del README (la misma comprobación que la vigilancia semanal: `scripts/vigilar-repositorio.sh`).
4. Los SHA-256 de la versión en el sitio de la app, junto a la huella de la clave.

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

- Plantillas de incidencia (fallo, propuesta, problema con un lector o un DNIe) que piden la versión, el lector y el informe de diagnóstico (RF-007), y advierten que no se adjunten PDF firmados ni capturas con el DNI completo.
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
- Clave del repositorio APT (DP-24, BRG-DSP-001 §4): maestra Ed25519 solo de certificación, `A99859F6A32D8D5DEE5D3609CEA6BD335F594929`, en dos memorias USB cifradas guardadas en lugares distintos, con su certificado de revocación; subclave de firma de dos años en la estación del titular. Sus frases de paso, en el gestor de contraseñas del titular.
  - Renovación: al menos tres meses antes de que caduque, se extiende la validez de la maestra y de la subclave con la maestra (`gpg --quick-set-expire`), y la clave renovada se publica como versión nueva de `noggalito-archive-keyring` en el repositorio, firmada todavía con la subclave vigente. Los usuarios la reciben con sus actualizaciones antes de la fecha.
  - Subclave comprometida o perdida: se revoca con la maestra, se crea otra y se publica igual que una renovación; los usuarios no hacen nada.
  - Maestra comprometida: se publica su revocación y una clave nueva, se avisa en el sitio y en las notas de versión, y los usuarios repiten la instalación a mano de BRG-DSP-001 §4 con la huella nueva.
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
- Inventario de credenciales y segunda persona mantenedora (documentación interna).
