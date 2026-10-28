# Empaquetado para Debian

| Campo | Valor |
|---|---|
| Documento | BRG-DSP-001 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-27 |
| Responsable | `{{TITULAR}}` |

## 1. Paquetes binarios

| Paquete | Contenido | Depends (preliminar) | Recommends |
|---|---|---|---|
| `berigna` | Aplicación, recursos, almacén de confianza, traducciones, manual | `python3 (>= 3.12)`, `python3-gi`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`, `gir1.2-poppler-0.18`, `python3-pyhanko (>= 0.25.1), python3-pyhanko (<< 0.26)` (\*), `python3-pyhanko-certvalidator`, `python3-pyscard`, `python3-pkcs11`, `python3-cryptography`, `python3-asn1crypto`, `python3-lxml`, `python3-signxml`, `python3-requests`, `python3-pil`, `python3-babel`, `python3-reportlab`, `pcscd` | `berigna-nautilus`, `libccid`, `opensc-pkcs11` (*backend* PKCS#11, ADR-0012) |
| `berigna-nautilus` | Extensión de Nautilus | `berigna (= ${binary:Version})`, `python3-nautilus` | — |
| `python3-pyhanko` (\*) | pyHanko 0.25.1 | Las dependencias oficiales de Debian 13 (SPK-05) | — |

Un paquete separado `python3-berigna-core` es una alternativa abierta (arquitectura §8); no está en el plan de la v1.

(\*) No está en Debian 13. Se empaqueta en el repositorio del proyecto (DP-06, ADR-0013).

Los tres paquetes son `Architecture: all` (DP-08).

## 2. Archivos instalados

| Ruta | Origen |
|---|---|
| `/usr/bin/berigna` | Lanzador |
| `/usr/lib/python3/dist-packages/berigna/` | Código |
| `/usr/share/berigna/` | GResource, almacén de confianza |
| `/usr/share/applications/pe.berigna.Berigna.desktop` | Entrada de escritorio con `MimeType=application/pkcs7-signature;application/pkcs7-mime;application/pdf;application/xml;` |
| `/usr/share/metainfo/pe.berigna.Berigna.metainfo.xml` | AppStream |
| `/usr/share/glib-2.0/schemas/pe.berigna.Berigna.gschema.xml` | GSettings |
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

## 5. Compilación reproducible y verificación

Herramienta candidata (a evaluar en la Fase 5): [Debcraft](https://optimizedbyotto.com/post/debcraft-1-0-released/) construye el `.deb` en contenedores efímeros (Podman o Docker), aislados de la red durante la compilación, con la distribución de `debian/changelog` y las dependencias de `debian/control`, y compara los artefactos entre compilaciones. Debian 13 ofrece la versión 0.5.0 (`apt install debcraft`); la 1.0 es posterior. No publica repositorios APT: para eso hará falta otra herramienta (por ejemplo, reprepro o aptly).

- Compilación en un entorno limpio con `sbuild` (o `debuild` en un *chroot*), con `SOURCE_DATE_EPOCH` fijado.
- Verificación con `reprotest`.
- `lintian --pedantic` sin errores ni avisos injustificados.
- `piuparts` para comprobar la instalación, la actualización y la purga.

## 6. Futuro: Fedora y similares

- `berigna.spec` sobre el mismo `meson.build`. Dependencias equivalentes: `pcsc-lite`, `pcsc-lite-ccid`, `opensc`, `python3-gobject`, `gtk4`, `libadwaita`, `nautilus-python`.
- Distribución inicial mediante COPR.
- Evaluación de Flatpak: hace falta acceso al *socket* de `pcscd` (`--socket=pcsc`) y comprobar la disponibilidad del módulo PKCS#11 dentro del *sandbox*.
