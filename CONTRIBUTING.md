# Cómo contribuir a berigna

Gracias por tu interés. berigna firma documentos con valor legal, así que pedimos cuidado con tres cosas: la seguridad, los datos personales y las pruebas.

Al participar aceptas el [código de conducta](CODE_OF_CONDUCT.md).

## Antes de empezar

- Para un cambio grande (un formato, un *backend*, una pantalla nueva), abre primero una incidencia con la propuesta. Así evitamos trabajo que no encaje con la hoja de ruta o con la acreditación.
- Lee el [entorno de desarrollo y las convenciones](docs/08-desarrollo/entorno-y-convenciones.md), los [requisitos](docs/03-requisitos/requisitos-funcionales.md) y la [arquitectura](docs/04-arquitectura/arquitectura-general.md).
- Una vulnerabilidad no se reporta en una incidencia pública: sigue la [política de seguridad](SECURITY.md).

## Datos personales y PIN

- **Nunca subas datos personales**: ni en el código ni en las incidencias, los PR, las capturas o los registros. Eso incluye números de DNI, nombres que salen de un certificado, certificados personales y documentos firmados con un DNIe real.
- Para reproducir un fallo usa el simulador del DNIe (`tests/sim/`) o la PKI de pruebas (`spikes/spk03/spk03_pki.py`). El informe del diagnóstico de berigna (menú principal → Diagnóstico → Copiar el informe) ya enmascara los números.
- No pruebes con un PIN real sin seguir antes el [protocolo de pruebas con PIN](docs/07-calidad/protocolo-pruebas-con-pin.md). Unos pocos intentos fallidos bloquean el DNIe.

## Flujo de trabajo

1. Crea una rama desde `main`: `feat/…`, `fix/…` o `docs/…`.
2. Haz commits según [Conventional Commits](https://www.conventionalcommits.org/es/v1.0.0/), firmados con el DCO (`git commit -s`, ver abajo).
3. Antes de abrir el PR, ejecuta `scripts/verificar.sh`: ruff, mypy estricto y pytest, con una cobertura mínima del 80 %.
4. Abre el PR contra `main` y completa la plantilla. La CI debe quedar en verde.

Los cambios en `core/token`, `core/formats`, `core/trust` o que afecten a la seguridad necesitan una revisión adicional.

## Textos y traducciones

El texto fuente de la interfaz está en inglés, dentro de `_()`. Toda cadena nueva llega en el mismo PR con:

- su traducción en `po/es_PE.po`;
- su entrada en `po/quz.po`, traducida con el [glosario quechua](docs/06-ux/glosario-quechua.md) o marcada como pendiente.

Una entrada pendiente bloquea la publicación de una versión. Detalle en las convenciones, §3.

## Certificado de origen (DCO) y licencia

Cada commit lleva una línea `Signed-off-by: Nombre <correo>`, que añade `git commit -s`. Con ella certificas lo que dice el [Developer Certificate of Origin 1.1](https://developercertificate.org/): que tienes derecho a enviar el cambio bajo la licencia del proyecto.

Tus contribuciones se publican bajo la misma licencia que el resto de berigna: GPL-3.0-or-later ([`LICENSE`](LICENSE)) con el permiso adicional para tiendas de aplicaciones ([`LICENSE-EXCEPTION.md`](LICENSE-EXCEPTION.md), ADR-0021). Conservas los derechos de autor sobre tu código.
