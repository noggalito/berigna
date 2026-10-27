# Política de seguridad

berigna firma documentos con valor legal. Tomamos en serio cualquier fallo que pueda afectar a la clave privada, al PIN, a la integridad de los documentos o al resultado de una verificación.

## Versiones con soporte

El proyecto está en desarrollo (Fase 1). Todavía no hay versiones publicadas. Cuando las haya, esta sección indicará cuáles reciben correcciones de seguridad.

## Cómo reportar una vulnerabilidad

- **No abras una incidencia pública.** Escribe a `{{CONTACTO_SEGURIDAD}}` con una descripción, los pasos para reproducirla y el impacto que estimas.
- Si la prueba requiere un DNIe, **no envíes nunca un PIN, certificados personales ni documentos firmados con datos reales.** Usa la PKI de pruebas del repositorio (`spikes/spk03/spk03_pki.py`) o el simulador (`tests/sim/`).
- Acusaremos recibo en un plazo de 5 días hábiles y acordaremos contigo una fecha de divulgación coordinada (90 días por defecto).

## Alcance

Entran en el alcance, entre otros: exposición o persistencia del PIN; firmas hechas sin el consentimiento del titular o sobre contenido distinto del mostrado; sesiones de la tarjeta que quedan autenticadas; envío al chip de instrucciones no permitidas; validaciones que aceptan firmas manipuladas; y fallos de integridad de los paquetes distribuidos.

El modelo de amenazas está en [`docs/05-seguridad/modelo-de-amenazas.md`](docs/05-seguridad/modelo-de-amenazas.md).
