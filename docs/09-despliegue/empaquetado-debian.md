# Empaquetado para Debian

| Campo | Valor |
|---|---|
| Documento | BRG-DSP-001 |
| Versión | 0.3.0 |
| Estado | Borrador |
| Fecha | 2026-11-04 |
| Responsable | noggalito |

## 1. Paquetes binarios

| Paquete | Contenido | Depends (preliminar) | Recommends |
|---|---|---|---|
| `berigna` | Aplicación, recursos, almacén de confianza, traducciones, manual | `python3 (>= 3.12)`, `python3-gi`, `python3-gi-cairo`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`, `gir1.2-poppler-0.18`, `python3-pyhanko (>= 0.25.1), python3-pyhanko (<< 0.26)` (\*), `python3-pyhanko-certvalidator`, `python3-pyscard`, `python3-cryptography`, `python3-asn1crypto`, `python3-lxml`, `python3-signxml`, `python3-requests`, `python3-pil`, `python3-reportlab`, `fonts-dejavu-core`, `pcscd` | `berigna-nautilus`, `libccid`, `opensc-pkcs11` (*backend* PKCS#11, ADR-0012) |
| `berigna-nautilus` | Extensión de Nautilus | `berigna (= ${binary:Version})`, `python3-nautilus` | — |
| `python3-pyhanko` (\*) | pyHanko 0.25.1 | Las dependencias oficiales de Debian 13 (SPK-05) | — |

Un paquete separado `python3-berigna-core` es una alternativa abierta (arquitectura §8); no está en el plan de la v1.

(\*) No está en Debian 13. Se empaqueta en el repositorio del proyecto (DP-06, ADR-0013).

Los tres paquetes son `Architecture: all` (DP-08). `python3-pkcs11` se añadirá en la versión 1.1, con el *backend* PKCS#11 (ADR-0003, DP-15); `python3-babel` se quitó el 2026-10-29: berigna no lo usa.

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

## 4. Repositorio APT

- Alojado en `{{URL_REPOSITORIO}}` (pendiente), con la estructura `dists/trixie/main/binary-amd64`.
- Firmado con una clave GPG dedicada del proyecto. La clave pública se distribuye con un paquete `berigna-archive-keyring` y se configura con `signed-by` en un archivo `.sources` (formato deb822).
- Instalación prevista para el usuario final:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL {{URL_REPOSITORIO}}/berigna-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/berigna.gpg > /dev/null
sudo tee /etc/apt/sources.list.d/berigna.sources > /dev/null <<'EOF'
Types: deb
URIs: {{URL_REPOSITORIO}}
Suites: trixie
Components: main
Signed-By: /etc/apt/keyrings/berigna.gpg
EOF
sudo apt update && sudo apt install berigna berigna-nautilus
```

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

## 6. Futuro: Fedora y similares

- `berigna.spec` sobre el mismo `meson.build`. Dependencias equivalentes: `pcsc-lite`, `pcsc-lite-ccid`, `opensc`, `python3-gobject`, `gtk4`, `libadwaita`, `nautilus-python`.
- Distribución inicial mediante COPR.
- Flatpak, a partir de la versión 1.1 (ADR-0006): hace falta acceso al *socket* de `pcscd` (`--socket=pcsc`) y comprobar la disponibilidad del módulo PKCS#11 dentro del *sandbox*. La extensión de Nautilus no puede ir dentro del Flatpak.
