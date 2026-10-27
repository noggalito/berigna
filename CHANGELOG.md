# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado semántico.

## [Sin publicar]

### Añadido

- Esqueleto del núcleo `berigna.core` (paquete `src/`, configuración de ruff, mypy estricto y pytest).
- Driver APDU del DNIe v2 (`berigna.core.token.dnie_v2`, ADR-0012): lista blanca de instrucciones, lectura del certificado parando en la longitud DER, VERIFY de un solo intento, firma PKCS#1 v1.5 sobre SHA-256/384/512.
- Transporte PC/SC (`berigna.core.token.transport`) con conexión exclusiva y apagado de la tarjeta al cerrar.
- Tipo `Pin` que no se muestra, no se serializa y se borra tras usarlo.
- Simulador del *applet* PKI del DNIe v2 para las pruebas automatizadas, y pruebas HIL de solo lectura.
- Lista blanca estricta por forma de comando (AID, archivos, referencia de PIN, plantilla de MSE, `DigestInfo`), con pruebas de *fuzzing*.
- Errores ERR-105 (tarjeta retirada), ERR-106 (tarjeta en uso por otro programa), ERR-107 (servicio PC/SC no disponible) y ERR-108 (fallo transitorio): pyscard ya no llega a las capas superiores.
- Reintento acotado de SELECT y READ BINARY ante fallos transitorios tras el apagado de la tarjeta; VERIFY y PSO:CDS no se reintentan nunca.
- `DnieV2Token.authenticated` y `DnieV2Token.probe_alive()` para el diagnóstico (RF-007).
- Umbral de cobertura del 80 % con cobertura de ramas.
