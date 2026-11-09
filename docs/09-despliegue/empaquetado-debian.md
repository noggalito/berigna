# Empaquetado para Debian

| Campo | Valor |
|---|---|
| Documento | BRG-DSP-001 |
| Versión | 0.10.0 |
| Estado | Borrador |
| Fecha | 2026-11-08 |
| Responsable | noggalito |

## 1. Paquetes binarios

| Paquete | Contenido | Depends | Recommends |
|---|---|---|---|
| `berigna` | Aplicación, recursos, almacén de confianza, traducciones, manual | `python3 (>= 3.12)`, `python3-gi`, `python3-gi-cairo`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`, `gir1.2-poppler-0.18`, `python3-pyhanko (>= 0.25.1), python3-pyhanko (<< 0.25.2~)` (\*), `python3-pyhanko-certvalidator (>= 0.26.3), (<< 0.27~)`, `python3-pyscard (>= 2.2)`, `python3-cryptography (>= 42)`, `python3-asn1crypto (>= 1.5), (<< 2~)`, `python3-lxml (>= 5)`, `python3-signxml (>= 4.0), (<< 5~)`, `python3-requests (>= 2.31)`, `python3-pil (>= 10)`, `python3-reportlab (>= 4)`, `fonts-dejavu-core`, `pcscd` | `berigna-nautilus`, `libccid`, `opensc-pkcs11` (*backend* PKCS#11, ADR-0012) |
| `berigna-nautilus` | Extensión de Nautilus | `berigna (= ${binary:Version})`, `python3-nautilus` | — |
| `python3-pyhanko` (\*) | pyHanko 0.25.1 | Las dependencias oficiales de Debian 13 (SPK-05) | — |

Un paquete separado `python3-berigna-core` es una alternativa abierta (arquitectura §8); no está en el plan de la v1.

(\*) No está en Debian 13. Se empaqueta en el repositorio del proyecto (DP-06, ADR-0013).

Los tres paquetes son `Architecture: all` (DP-08). Los límites de versión son los de `pyproject.toml` (desde el 2026-11-08, ADR-0023): `scripts/verificar-dependencias.py` comprueba en la CI que `debian/control` los repite (`>=V` es `(>= V)`; `~=V` añade el techo de PEP 440; `==V` admite solo las revisiones de Debian de V; los techos llevan `~`, para que tampoco pase una versión previa como `0.27~rc1`, que dpkg ordena antes de `0.27`), para que `apt` rechace una distribución que no los cumple. La lista de `Depends` quedó confirmada con el incremento 3 (2026-11-05): el paquete `berigna` se construye, se instala y se verifica en Debian 13 con ella (§7). `berigna-nautilus` llegó con el incremento 4 (2026-11-06, §8); mientras no esté en el repositorio, la instalación con `--no-install-recommends` no lo pide (apt ignora los `Recommends` ausentes). `python3-pkcs11` se añadirá en la versión 1.1, con el *backend* PKCS#11 (ADR-0003, DP-15); `python3-babel` se quitó el 2026-10-29: berigna no lo usa.

## 2. Archivos instalados

| Ruta | Origen |
|---|---|
| `/usr/bin/berigna` | Lanzador |
| `/usr/lib/python3/dist-packages/berigna/` | Código |
| `/usr/share/berigna/` | GResource, almacén de confianza |
| `/usr/share/applications/com.noggalito.Berigna.desktop` | Entrada de escritorio con `MimeType=application/pkcs7-signature;application/pkcs7-mime;application/pdf;application/xml;` |
| `/usr/share/metainfo/com.noggalito.Berigna.metainfo.xml` | AppStream |
| `/usr/share/glib-2.0/schemas/com.noggalito.Berigna.gschema.xml` | GSettings |
| `/usr/share/icons/hicolor/…` | Iconos |
| `/usr/share/locale/es_PE/LC_MESSAGES/berigna.mo` | Traducción es_PE |
| `/usr/share/locale/es/LC_MESSAGES/berigna.mo` | El mismo catálogo es_PE, como respaldo para cualquier variante del español (ADR-0011) |
| `/usr/share/help/C/berigna/` | Manual en es_PE (respaldo, ADR-0015) |
| `/usr/share/help/quz/berigna/` | Manual en quechua sureño |
| `/usr/share/help/es_PE/berigna/` y `/usr/share/help/es/berigna/` | Manual en es_PE |
| `/usr/share/nautilus-python/extensions/berigna_nautilus.py` | Extensión (paquete `berigna-nautilus`) |

## 3. Integración con el sistema

- `pcscd` se activa por *socket* en Debian (`pcscd.socket`). El paquete no debe forzar su habilitación, pero el diagnóstico (RF-007) comprueba su estado.
- No hacen falta *scripts* de mantenimiento (`postinst`) más allá de los que genera debhelper (iconos, esquemas, MIME y escritorio se gestionan con *triggers*).
- No se crean usuarios ni grupos, y no hay servicios propios.
- El `.desktop` y la metainfo de AppStream llevan su nombre, su descripción y sus palabras clave en es_PE y en quechua (`Name[quz]=`, `xml:lang="quz-PE"`), generados con gettext desde `po/`. El valor sin etiqueta de idioma, que es el de respaldo, se genera desde el catálogo es_PE (ADR-0015).
- `lintian` y `appstreamcli validate` deben pasar con ambos idiomas.

## 4. Repositorio APT (DP-24, 2026-11-08)

Un solo repositorio, una sola clave y una sola fuente para todas las apps de noggalito: quien ya lo tiene configurado instala la siguiente app con `apt install`, sin otra clave. Lo específico de cada app (la huella, los SHA-256 de cada versión, las instrucciones) se publica en su sitio; el de berigna es `https://berigna.noggalito.com`.

- URL: `https://noggalito.com/apps/deb/`. Son archivos estáticos que sirve el servidor web delante del sitio, nunca el sitio: el repositorio no depende de él. Delante hay una CDN: los índices de `dists/` no se guardan en caché y los `.deb` de `pool/` sí, por un año, porque una versión publicada no cambia nunca. La ruta está exenta de los desafíos anti-bots de la CDN, porque `apt` no ejecuta JavaScript.
- Una suite, `stable`, y un componente, `main`, para toda la familia Debian (ADR-0023). Los paquetes son `Architecture: all` y aparecen en los índices de `amd64` y `arm64`.
- Se arma sin estado con `apt-ftparchive` (`scripts/armar-repositorio.sh`): `dists/` se regenera entero desde `pool/` en cada publicación, con `Acquire-By-Hash`, para que un cliente que actualiza durante una publicación nunca mezcle índices viejos y nuevos. El `Release` declara `Signed-By` con la huella de la clave. Un `.deb` ya publicado no se reemplaza: el mismo nombre con otro contenido es un error. Sin `Valid-Until`, a propósito: obligaría a volver a firmar cada pocas semanas aunque no haya versión nueva, y la firma se hace a mano con una clave que no sale de la estación del titular. Se revisa si la firma pasa a ser automática. Las copias `by-hash` de índices reemplazados hace más de dos semanas se borran al publicar.
- Clave OpenPGP de noggalito (`paquetes@noggalito.com`): maestra Ed25519 solo de certificación, `A99859F6A32D8D5DEE5D3609CEA6BD335F594929`, guardada fuera de línea; subclave de firma Ed25519 `E21F94C58091EC144E40066E3F89E15C95A9B4F4`, válida hasta el 2028-11-08. La renovación y la rotación están en BRG-MAN-001 §7.
- El paquete `noggalito-archive-keyring` (en `packaging/noggalito-archive-keyring/`, versión por fecha) instala la clave en `/usr/share/keyrings/noggalito-archive-keyring.asc` y la fuente deb822 `/etc/apt/sources.list.d/noggalito.sources`, con `Signed-By` hacia esa clave sola. Una clave renovada llega como actualización de este paquete, antes de que caduque la anterior.
- Firma y publicación (`scripts/publicar-repositorio.sh`), en la estación del titular, la única con la subclave: comprueba los `.deb` contra su `SHA256SUMS`, trae `pool/` del servidor, arma, firma `InRelease` y `Release.gpg` y los comprueba con `sqv`, el verificador de `apt` (`scripts/firmar-repositorio.sh`); sube primero `pool/`, después los índices y sus copias `by-hash`, y al final los `Release` firmados; y comprueba a través de la CDN que el `InRelease` publicado es el firmado. La CI no tiene ninguna credencial del servidor.
- La CI prueba el repositorio con una clave de prueba en Debian 13 y en Ubuntu 26.04 (`scripts/probar-repositorio.sh`, trabajo `repositorio`): instalación con la firma aceptada, actualización a una versión posterior, rechazo de un `Release` alterado y de uno firmado con otra clave, rechazo de un `.deb` publicado con otro contenido, e instalación de `noggalito-archive-keyring` sobre la instalación a mano sin preguntas.

Instalación para el usuario final:

```bash
sudo curl -fsSLo /usr/share/keyrings/noggalito-archive-keyring.asc \
  https://noggalito.com/apps/deb/noggalito-archive-keyring.asc
gpg --show-keys /usr/share/keyrings/noggalito-archive-keyring.asc
#   la huella debe ser A99859F6A32D8D5DEE5D3609CEA6BD335F594929
sudo curl -fsSLo /etc/apt/sources.list.d/noggalito.sources \
  https://noggalito.com/apps/deb/noggalito.sources
sudo apt update && sudo apt install berigna noggalito-archive-keyring
```

`berigna-nautilus` llega como recomendación de `berigna`. Desde ese momento, `noggalito-archive-keyring` mantiene la clave y la fuente.

## 4 bis. Archivo oficial de Debian (ADR-0020)

Desde la v1.0 estable se solicita la entrada de berigna en Debian. Orden de trabajo:

1. Comprobar en WNPP si alguien ya pidió pyHanko; si no, abrir el ITP de `python3-pyhanko` y empaquetarlo en el equipo de Python de Debian (salsa.debian.org).
2. Abrir el ITP de `berigna` y llevar el empaquetado de este documento a salsa, con `debian/watch`, `debian/upstream/metadata`, `autopkgtest` y la metainfo de AppStream.
3. Publicar el paquete fuente en mentors.debian.net y pedir patrocinio (RFS) en la lista del equipo de Python.
4. Revisión de la cola NEW por los ftpmasters (licencias y `debian/copyright`); después, *unstable* → *testing* → *trixie-backports*.
5. Resolver antes las tipografías incluidas (ADR-0020, requisito 2).

El campo `Maintainer` debe ser una dirección que lea una persona (`berigna@noggalito.com` sirve si llega al titular) o la lista del equipo de Python, con quien sube el paquete en `Uploaders`.

## 5. Compilación reproducible y verificación

Evaluadas en el incremento 2 (2026-11-04) para `python3-pyhanko`, con el procedimiento
escrito en `scripts/empaquetar-pyhanko.sh`:

- [Debcraft](https://optimizedbyotto.com/post/debcraft-1-0-released/) 0.5.0 (en Debian 13,
  `apt install debcraft`) construye el `.deb` en contenedores efímeros (Podman o Docker),
  con la distribución de `debian/changelog` y las Build-Depends de `debian/control`
  instaladas dentro del contenedor, y compara los artefactos entre dos compilaciones.
  Para un directorio de fuentes sin git se usa `debcraft build --skip-sources`: el tarball
  orig del formato `3.0 (quilt)` no es visible dentro del contenedor.
- `debuild` (de `devscripts`) produce además el paquete fuente completo (`.dsc`, orig y
  `.debian.tar.xz`), que es lo que se subirá a Debian (ADR-0020); requiere las
  Build-Depends instaladas en el equipo y el tarball orig con nombre Debian junto al árbol.
- `SOURCE_DATE_EPOCH` se fija con la fecha del empaquetado en el repositorio.

Resultados con `python3-pyhanko` 0.25.1: `lintian --pedantic` sin errores (un aviso
esperado, `initial-upload-closes-no-bugs`, hasta que la subida a Debian cierre el ITP
#1062808); `piuparts` pasa en un trixie mínimo; el paquete se instala con las dependencias
de Debian y funciona (`import pyhanko`, el CLI y su página de manual).

## 5 bis. Un solo `.deb` para la familia Debian (2026-11-08)

Un entregable por formato, no por distribución: el mismo `berigna_X.Y.Z-1_all.deb`, con `python3-pyhanko` y `berigna-nautilus`, se instala en cualquier distribución de la familia Debian que satisfaga sus dependencias, sin sufijos `~ubuntu…` ni suites por distribución. Se puede porque los tres paquetes son `Architecture: all`, Python puro: `dh_python3` no pone techo a la versión de Python (`python3 (>= 3.12)`) y la byte-compilación se hace al instalar, con el Python del sistema. Dónde está soportado lo dice la matriz de pruebas, no el paquete.

La CI compila los paquetes una sola vez, en Debian 13 (la base más antigua), en el trabajo `paquetes` (`scripts/compilar-paquetes.sh`, que llama a `scripts/empaquetar-*.sh debuild` y deja el `SHA256SUMS`), y el trabajo `ubuntu-26-04` instala ese mismo artefacto en un contenedor `ubuntu:26.04` y ejecuta la suite completa contra el paquete instalado (`scripts/probar-paquete-instalado.sh`: `berigna` se importa de `/usr/lib/python3/dist-packages`, nunca de `src/`; las vistas, el esquema y los catálogos son los instalados). Antes de la suite importa todos los módulos del paquete con los avisos de berigna convertidos en errores: una biblioteca de la distribución que declare obsoleto algo que berigna usa se ve ahí antes de romperlo. Un fallo se ve en rojo en el PR; solo `verificar` es obligatorio para fusionar hasta la Fase 6, en que `ubuntu-26-04` se suma (Ubuntu 26.04 soportada desde la v1.0, ADR-0023). El trabajo `ubuntu-24-04` comprueba el otro lado: `scripts/probar-rechazo.sh` simula la instalación en `ubuntu:24.04` y exige que `apt` la rechace nombrando `python3-cryptography`, `python3-pyscard` y `python3-signxml`. Los tres trabajos están en `.github/workflows/paquetes.yml`, que llaman la CI de cada PR y la vigilancia semanal (BRG-MAN-001 §5); esta los repite con las actualizaciones de Ubuntu (*resolute-updates* y *resolute-security*) y abre una incidencia si fallan.

Resultado del 2026-11-08 en Ubuntu 26.04.1 (Python 3.14.4, cryptography 46.0.5, lxml 6.0.2, pyscard 2.3.1, signxml 4.2.0, libadwaita 1.9, xmlsec1 1.3.9): 784 pruebas en verde, 5 omitidas (HIL) y una excluida (la del SBOM, que describe el entorno de la CI y no un sistema instalado). Lo que apareció por el camino:

- Nautilus 50 (Ubuntu 26.04) publica su API como `Nautilus 4.1`; Nautilus 48 (Debian 13), como 4.0. La extensión pedía solo la 4.0 y en Ubuntu no se cargaba (sin menú). Desde el 2026-11-08 pide la 4.1 y, si no está, la 4.0; `python3-nautilus` arrastra la typelib de cada distribución. Lo encontró la importación con avisos como errores, no la suite, que usa un Nautilus simulado.
- La imagen de contenedor de Ubuntu está minimizada: `dpkg` descarta `/usr/share/locale` y con él los catálogos de berigna. Una instalación real los conserva; el script quita esa regla antes de instalar.
- xmlsec1 1.3 lee solo el primer certificado de un archivo PEM: la prueba pasa cada ancla en su archivo (con la 1.2.41 de Debian 13 da igual).
- libadwaita 1.9 devuelve el subtítulo de una fila con su marcado (`<b>berigna</b>`) y la 1.7 sin él: la prueba compara el texto.
- cryptography 46 avisa de que tres raíces extranjeras de la TSL real de INDECOPI (dos de GSE, Colombia, y la de Indenova, España) tienen número de serie 0, prohibido por RFC 5280, y de que una versión futura no las leerá. `core.trust.tsl` ya descarta con `ValueError` un certificado que no se puede leer: con esa versión, esas tres CA dejarían de ser de confianza, sin afectar a la carga de la lista ni a las CA peruanas. `test_a_root_with_serial_number_zero_is_still_kept` fija que hoy se conservan: falla el día que cryptography las rechace, para que descartarlas sea una decisión del titular y no un cambio silencioso.
- Avisos de obsolescencia ajenos a berigna: signxml 4.2 (curvas binarias de cryptography) y PyGObject (API de asyncio que Python 3.16 retirará).

Ubuntu 24.04 y Linux Mint 22 quedan fuera: no traen signxml y sus versiones de cryptography, pyscard y libadwaita están por debajo de los mínimos.

## 6. Futuro: Fedora y similares

- `berigna.spec` sobre el mismo `meson.build`. Dependencias equivalentes: `pcsc-lite`, `pcsc-lite-ccid`, `opensc`, `python3-gobject`, `gtk4`, `libadwaita`, `nautilus-python`.
- Distribución inicial mediante COPR.
- Flatpak, a partir de la versión 1.1 (ADR-0006): hace falta acceso al *socket* de `pcscd` (`--socket=pcsc`) y comprobar la disponibilidad del módulo PKCS#11 dentro del *sandbox*. La extensión de Nautilus no puede ir dentro del Flatpak.

## 7. El paquete `berigna` (incremento 3, 2026-11-05)

`debian/` vive en la raíz del repositorio (como preveía BRG-DES-001 §1):

| Archivo | Contenido |
|---|---|
| `debian/control` | Fuente 3.0 (quilt); `Build-Depends` para Meson con dh-python (`debhelper-compat (= 13)`, `meson`, `ninja-build`, `blueprint-compiler` con los typelibs `gir1.2-gtk-4.0` y `gir1.2-adw-1` que las vistas importan, `gettext`, `libglib2.0-dev`, `gtk-update-icon-cache`, `desktop-file-utils`, `appstream`, `python3`); el `Depends` de §1 |
| `debian/rules` | `dh $@ --with python3 --buildsystem=meson`; `dh_auto_test` ejecuta las pruebas de Meson (`desktop-file-validate` y `appstreamcli validate`); `dh_installdocs` añade la página de manual, como en `python3-pyhanko` |
| `debian/copyright` | DEP-5: GPL-3.0-or-later para el código y la marca, SIL OFL 1.1 con el texto completo para las 4 tipografías (Arvo y Source Sans 3, con los nombres reservados de cada licencia) y los certificados públicos de la IOFE (RENIEC e INDECOPI) como datos públicos con su origen |
| `debian/changelog` | `berigna (0.1.0~dev0-1) trixie`: la forma Debian de la versión de `meson.build` (`0.1.0.dev0`) |
| `debian/berigna.1` | Página de manual: sinopsis, opciones, instancia única (RF-073) y carpetas de datos |

Decisión de las tipografías (ADR-0020, requisito 2): se mantienen las copias incluidas de Arvo y Source Sans 3 en TrueType y se justifican en `debian/copyright`. Debian trae Source Sans 3 solo en OpenType/CFF (`fonts-adobe-sourcesans3`), que ReportLab no incrusta, y no trae Arvo. Para el archivo oficial de Debian la decisión se revisa con el patrocinador, como dice ADR-0020; si el titular prefiere el paquete `fonts-berigna`, se abre DP-21.

Compilación reproducible con `scripts/empaquetar-berigna.sh`, el mismo procedimiento que el de pyHanko (§5): exporta el árbol de git como tarball *orig* (sin `debian/`, como exige el formato 3.0 (quilt)), añade `debian/` y construye con debcraft (`--skip-sources`) o debuild, con `SOURCE_DATE_EPOCH` fijado en el último cambio del empaquetado. Resultados en Debian 13: `lintian --pedantic` sin errores (un aviso esperado, `initial-upload-closes-no-bugs`); `piuparts`, como en §5, en la VM:
`sudo piuparts -d trixie -b /var/cache/piuparts/base.tar.xz build/berigna_0.1.0~dev0-1_all.deb`.

Verificación con el paquete instalado: en un Debian 13 recién instalado, `apt install ./python3-pyhanko_0.25.1-1_all.deb ./berigna_0.1.0~dev0-1_all.deb` resuelve todas las dependencias con los paquetes de Debian más pyHanko del repositorio propio. La aplicación instalada se comprueba con las pruebas de la interfaz (Xvfb) contra el paquete instalado, incluidos el arrastrar y soltar (RF-072) y la apertura como argumento (RF-073), y en una sesión real la segunda invocación entrega el archivo a la instancia en marcha y termina (instancia única por D-Bus, RF-073). El icono, la entrada de escritorio con sus MIME (RF-071), la metainfo y los catálogos quedan instalados y validados (las pruebas de Meson de §3).

## 8. El paquete `berigna-nautilus` (incremento 4, 2026-11-06)

- `src/berigna_nautilus.py` (GPL-3.0-or-later): el proveedor de menú con las acciones "Firmar con berigna" (archivos y carpetas; varios, o una carpeta, abren el lote, CU-04) y "Verificar firma" (un solo archivo), con las etiquetas del catálogo de berigna (ADR-0011, ADR-0015) y el icono simbólico; lanza la entrada de escritorio `com.noggalito.Berigna.desktop` con la selección (RF-073) y nunca lee los archivos. Sin archivos locales no ofrece nada (berigna no abre ubicaciones remotas).
- Meson (`src/meson.build`) lo instala en `/usr/share/nautilus-python/extensions/berigna_nautilus.py`, donde lo busca `python3-nautilus`; no va al directorio de Python de la distribución.
- `debian/control` añade el paquete binario `berigna-nautilus` (`Architecture: all`; Depends: `berigna (= ${binary:Version})`, `python3-nautilus`) y `debian/berigna-nautilus.install` le asigna la extensión; `debian/berigna.install` pasa a listar los archivos del paquete `berigna`, porque con un segundo paquete dh_install ya no reparte todo en el primero por defecto. El `Recommends` de `berigna` ya apuntaba a él (§1).
- Pruebas: `tests/unit/test_nautilus.py` ejercita el proveedor con Nautilus, Gio y GObject simulados (100 % de cobertura), de modo que la suite no necesita `python3-nautilus`; la emisión real de la señal "activate" se simula con `callback(item, files)` (un manejador que no esperaba el elemento de menú dejó las acciones sin efecto; corregido el 2026-11-06). La extensión se byte-compila en el `postinst` con una segunda llamada a `dh_python3` con el directorio privado (`debian/rules`), de modo que `adequate` ya no la marca como `py-file-not-bytecompiled`; por eso `berigna-nautilus` lleva `${python3:Depends}` (dh_python3 solo actúa sobre paquetes que lo listan). Verificado el 2026-11-06 en la estación de trabajo Debian 13: `lintian --pedantic` sin errores (los dos avisos esperados `initial-upload-closes-no-bugs` y las notas informativas de las tipografías, DP-21) y `piuparts` con los tres paquetes juntos, que termina en PASS; un WARN no bloqueante: los enlaces rotos de `python3-reportlab` a las DejaVu Condensed (vicio del paquete de Debian: apuntan a `fonts-dejavu-extra`, no instalado). Probada en GNOME real (2026-11-06): las dos acciones con un archivo, el lote con varios y con una carpeta; la VM del criterio de salida de la fase (incremento 6) la repetirá desde el repositorio.
