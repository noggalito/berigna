# Publicación de versiones

| Campo | Valor |
|---|---|
| Documento | BRG-DES-003 |
| Versión | 0.1.0 |
| Estado | Borrador |
| Fecha | 2026-11-09 |
| Responsable | noggalito |

## 1. Propósito

Reunir en un solo lugar el proceso completo de publicar una versión de berigna, hoy repartido entre BRG-DES-001 §6 (versionado), BRG-DSP-001 §4 (repositorio APT) y cuatro comandos sueltos. El guion `scripts/publicar-version.sh` encadena la parte final; este documento explica cada paso, los requisitos previos y qué hacer cuando algo falla.

## 2. Requisitos previos

- La versión ya entró en `main` por PR: `scripts/version.py preparar <versión>` escribe la versión en los seis sitios y cierra la sección "Sin publicar" del CHANGELOG; el diff se revisa y se fusiona como cualquier otro cambio (BRG-DES-001 §6).
- `main` limpio e igual a `origin/main`, en la estación del titular.
- `gh` instalado y autenticado (`gh auth login`).
- La clave SSH con la que se firman los commits y las etiquetas, y la subclave OpenPGP Ed25519 de noggalito con la que se firma el repositorio (el guion pide su frase de paso).
- El alias ssh del servidor del repositorio (BRG-DSP-001 §4). El alias y su dirección están en la documentación interna, no en el repositorio; en la estación del titular aparecen en `~/.ssh/config`. El servidor correcto es el que aloja `https://noggalito.com/apps/deb/` y tiene `pool/` dentro de `DESTINO` (por defecto `/srv/paquetes/deb`); se comprueba con:

```bash
ssh <alias> 'ls -d /srv/paquetes/deb'
```

- `piuparts` con los tres paquetes, en la VM de Debian 13 (BRG-DSP-001 §8, §5 de este documento).

## 3. El flujo completo

Los tres primeros pasos son los de BRG-DES-001 §6; el cuarto los encadena el guion:

1. `scripts/version.py preparar <versión>`: escribe la versión en `pyproject.toml`, `meson.build`, `src/berigna/__init__.py`, `debian/changelog`, la metainfo de AppStream y el CHANGELOG, con la fecha. El cambio llega a `main` en un PR y se fusiona tras la revisión y la CI en verde.
2. Con `main` limpio e igual a `origin/main`: `scripts/version.py etiquetar <versión>`. Comprueba los seis sitios, pasa `scripts/verificar.sh`, construye `berigna` y `berigna-nautilus` con `scripts/empaquetar-berigna.sh` y `python3-pyhanko` con `scripts/empaquetar-pyhanko.sh` (todos con `lintian --pedantic`), deja los `.deb`, `SHA256SUMS` y `notas.md` en `build/version/v<versión>/` y pone la etiqueta firmada.
3. `piuparts` con los tres `.deb` en la VM de Debian 13 (necesita root), antes de publicar. Es el criterio de cierre del empaquetado y no puede correr en la estación normal.
4. Publicación, con el guion que encadena los tres comandos que antes se hacían a mano:

```bash
SERVIDOR=<alias-ssh> scripts/publicar-version.sh <versión>
```

El guion comprueba primero los requisitos (rama, árbol, `gh`, `SERVIDOR`, pregunta por `piuparts`), y después ejecuta, parando en el primer fallo:

1. `scripts/version.py etiquetar <versión>` (con los argumentos extra que reciba, por ejemplo `--constructor debuild`);
2. `git push origin v<versión>` — el gancho pre-push vuelve a pasar `verificar.sh`, como en cualquier push;
3. `gh release create` con los `.deb`, el `SHA256SUMS` y las `notas.md` de `build/version/v<versión>/` (añade `--prerelease` si la versión lleva guion, por ejemplo `1.0.0-rc.1`);
4. `scripts/publicar-repositorio.sh build/version/v<versión>`, que comprueba las sumas, trae el `pool/` publicado, arma el repositorio sin estado, lo firma (aquí `gpg` pide la frase de paso), lo comprueba con `sqv` y lo sube en el orden que nunca muestra un índice que apunte a un archivo que falta.

La vigilancia semanal confirma el lunes siguiente que el repositorio publicado sigue sano (clave, firma, instalación y versión al día; BRG-MAN-001 §5).

## 4. Situaciones habituales

- `version.py: el árbol de trabajo no está limpio`: se llamó a `etiquetar` (o al guion) con cambios sin confirmar. Confirmarlos o guardarlos; la versión se publica desde `main`.
- `estás en <rama>; la versión se publica desde main`: el guion exige `main` para no etiquetar un árbol mezclado. `git checkout main && git pull --ff-only`.
- `main no está al día con origin/main`: falta el `pull` tras fusionar el PR de `preparar`.
- `gh no está autenticado`: `gh auth login`.
- `falta SERVIDOR, el alias ssh del servidor`: se olvidó la variable. El alias no está en el repositorio a propósito; ver §2. El síntoma de haber puesto un alias inexistente es `ssh: Could not resolve hostname ...` seguido del fallo del `rsync`.
- `gpg: firma fallida: Operación cancelada`: se respondió "Cancelar" al cuadro de la frase de paso. Repetir la publicación; los pasos ya hechos (etiqueta subida, release creado) fallan al repetirse, así que en una repetición se usan los comandos sueltos desde el punto donde se quedó, o el guion con `PIUPARTS_OK=1` si lo que falta es solo el repositorio.
- `gh release create ... ya existe`: la etiqueta y el release ya están subidos; seguir desde `scripts/publicar-repositorio.sh build/version/v<versión>`.
- Un `.deb` publicado no se reemplaza nunca (BRG-DSP-001 §4): un fallo tras publicar se corrige en la versión siguiente.

## 5. piuparts en la VM

En la VM de Debian 13, con root, sobre los `.deb` de `build/version/v<versión>/` (copiarlos a la VM o montar la carpeta):

```bash
sudo piuparts -d trixie -b /var/cache/piuparts/base.tar.xz \
  berigna_<versión>-1_all.deb \
  berigna-nautilus_<versión>-1_all.deb \
  python3-pyhanko_0.25.1-1_all.deb
```

La primera vez en una VM nueva se usa `-s /var/cache/piuparts/base.tar.xz` para guardar la imagen base; después, `-b` la reutiliza. Se espera PASS con los tres juntos y el único WARN no bloqueante conocido de `python3-reportlab` (BRG-DSP-001 §8).

## 6. Checklist de cierre

- [ ] `git tag -v v<versión>` verifica la firma de la etiqueta
- [ ] El release de GitHub existe con los tres `.deb`, el `SHA256SUMS` y las notas
- [ ] El final de `scripts/publicar-repositorio.sh` confirma que el `InRelease` que sirve la CDN es el firmado (lo comprueba antes de terminar)
- [ ] `scripts/vigilar-repositorio.sh` (en un contenedor, con root) termina sin errores, o la vigilancia semanal lo confirma el lunes siguiente
