<!-- Qué cambia y por qué. Enlaza la incidencia si existe (Closes #…). -->

## Requisitos y decisiones

<!-- RF-xxx, RNF-xxx, ADR-xxxx o CU-xx afectados, si aplica. -->

## Comprobaciones

- [ ] `scripts/verificar.sh` pasa en local.
- [ ] Los commits siguen Conventional Commits y llevan `Signed-off-by` (DCO).
- [ ] Las cadenas nuevas tienen su traducción en `po/es_PE.po` y su entrada en `po/quz.po`.
- [ ] La documentación y `CHANGELOG.md` están al día (también la Fecha y la Versión de los documentos tocados).
- [ ] No hay datos personales: ni DNI, ni certificados, ni documentos firmados reales, ni capturas que los muestren.
- [ ] Si toca `core/token`, `core/formats`, `core/trust` o la seguridad, lo indico aquí para la revisión adicional.
- [ ] Si se probó con un DNIe real, fue según el protocolo de pruebas con PIN (BRG-CAL-002).
