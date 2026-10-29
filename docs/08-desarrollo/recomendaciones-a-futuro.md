# Recomendaciones a futuro sobre la práctica de desarrollo

| Campo | Valor |
|---|---|
| Documento | BRG-DES-002 |
| Versión | 0.2.0 |
| Estado | Borrador |
| Fecha | 2026-10-29 |
| Responsable | noggalito |

## 1. Propósito

Mejoras de la forma de trabajar (no de funciones), ordenadas por el momento en que conviene adoptarlas. Complementa el plan de mantenimiento (BRG-MAN-001), que ya prevé la vigilancia automática (§5), la continuidad (§10) y sus pendientes (§12): aquí no se repite lo que allí está, solo se remite a ello.

Punto de partida: el proyecto ya tiene ADR, trazabilidad de requisitos a pruebas, modelo de amenazas, protocolo de PIN, núcleo sin dependencia de la interfaz, mypy estricto, cobertura de ramas, catálogos exigidos por la CI, cabeceras SPDX y CHANGELOG. Las herramientas de desarrollo de la CI están fijadas a versiones exactas (`pytest`, `hypothesis`, `mypy`, `pytest-cov`, `ruff`, `pyHanko==0.25.1`) y el resto llega de Debian 13 en un contenedor: el entorno ya es reproducible en lo esencial, y no hace falta un archivo de bloqueo aparte.

## 2. Fase 4

| N.º | Recomendación | Por qué | Coste |
|---|---|---|---|
| R-DES-01 | Activar ya la vigilancia de BRG-MAN-001 §5: CI semanal contra Debian *stable* y *testing*, comprobación de la TSL y de los servicios de RENIEC, Dependabot solo para las *actions* | Hoy existe solo la CI de cada PR; la vigilancia es evidencia para la acreditación y para R-15 y R-17. El *script* de medición de R-17 (CE-09) es el embrión de la comprobación de RENIEC | Bajo |
| R-DES-02 | Vigilancia de vulnerabilidades adaptada a Debian: `debsecan` en el contenedor y las alertas de GitHub (GHSA y OSV) para pyHanko 0.25.1 | `pip-audit` sobre paquetes de Debian da falsos positivos (Debian corrige sin cambiar la versión de origen); lo único que llega de PyPI en producción es pyHanko | Bajo |
| R-DES-03 | Lista de componentes (SBOM, CycloneDX) generada en la CI | El expediente pide declarar los componentes de terceros y sus licencias; generada es más fiable que escrita a mano | Bajo |
| R-DES-04 | Plantillas de incidencia y de PR en `.github/` (BRG-MAN-001 §8 y §12) | Prometidas y aún inexistentes; piden la versión, el lector y el informe de diagnóstico, y avisan de no adjuntar PDF firmados ni el DNI | Trivial |
| R-DES-05 | Comprobación automática de la documentación en `scripts/verificar.sh`: tabla de cabecera completa, Fecha no anterior a la del último cambio (regla de BRG-GES-001 §2), identificadores citados (RF, RNF, CU, ADR, DP, ERR) que existen | Los desajustes del informe de revisión 0018 (cabeceras, una cita a RF-082 por RF-007) son de los que un *script* corto detecta siempre | Bajo |
| R-DES-06 | Gancho `pre-push` con `scripts/verificar.sh`, versionado en el repositorio (`git config core.hooksPath scripts/hooks`) | Un gancho opcional no se usa. No `pre-commit` (el programa): añadiría una dependencia de PyPI sin ganar nada | Trivial |

## 3. Antes de la versión 1.0

| N.º | Recomendación | Por qué | Coste |
|---|---|---|---|
| R-DES-07 | Pruebas por propiedades con Hypothesis (ya instalada en la CI) en las tres fronteras con datos de fuera: PDF y CMS mutados en `core.validation.pdf`, XML mutado en `core.trust.tsl`, respuestas OCSP y TSA truncadas | Los hallazgos A-3, M-2 y M-11 del informe 0018 eran de esta clase; la política de fronteras de BRG-DES-001 §3 queda así probada en general, no caso a caso. Adelanta parte del *fuzzing* previsto para la Fase 6 (AM-05, AM-06, AM-15) | Medio |
| R-DES-08 | CI semanal, sin bloquear, contra la última pyHanko de PyPI en una rama aparte | Mide cuánto cuesta salir de la 0.25.1 (R-15, ADR-0013) antes de Debian 14, en lugar de descubrirlo al migrar | Bajo |
| R-DES-09 | Proceso de versión escrito y en un *script*: etiqueta firmada (con la misma clave SSH de los commits), construcción del `.deb`, SHA-256, notas desde el CHANGELOG | La versión acreditada debe ser identificable (ACR-12); hoy no hay ninguna etiqueta. Se aplica ya a la versión candidata de la prueba de usabilidad (§6) | Medio |
| R-DES-10 | Medidas de rendimiento con la tarjeta simulada en la CI: firmar un PDF y un lote de 20, verificar un PDF B-LTA, abrir una carpeta de 200 PDF; aviso si empeoran más de un 50 % | RNF-REN está sin medir; un problema como M-1 (lectura en el hilo principal) se habría visto | Bajo |
| R-DES-11 | Registro local de fallos (§5) | Hoy una excepción no prevista fuera de los hilos protegidos se pierde | Bajo |

## 4. Fases 5 y 6

| N.º | Recomendación | Por qué | Coste |
|---|---|---|---|
| R-DES-12 | Paquete `.deb` reproducible (`reprotest` en la CI) | Lo exige en la práctica Debian oficial (ADR-0020) y le sirve al auditor: el paquete publicado se corresponde con el código | Medio |
| R-DES-13 | Revisión de accesibilidad con Orca en todas las vistas y comprobación del contraste en los temas claro y oscuro, con resultado registrado | RNF-USA-03 tiene la base (botones con nombre) pero no hay evidencia de uso real con lector de pantalla | Bajo |
| R-DES-14 | Continuidad (BRG-MAN-001 §10): réplica del repositorio fuera de GitHub, custodia y copia de las claves (commits, futuro repositorio APT), segunda persona con acceso | Con una sola persona mantenedora es el riesgo más alto y el más barato de reducir | Trivial |

## 5. Informes de fallos

Decisión: **no** se envían informes de fallos automáticos (ni Sentry, ni similares, ni con consentimiento). berigna maneja documentos, nombres y números de DNI; RNF-SEG-07 prohíbe conexiones no solicitadas y el modelo de amenazas (AM-11) cuenta con que no salga nada más que *hash* e identificadores. Un servicio externo añadiría un tercero que trata datos personales y una superficie más ante el evaluador, para un volumen de usuarios con el que basta un canal manual.

Sí vale la pena el **registro local de fallos** (R-DES-11):

1. `sys.excepthook` y `threading.excepthook` escriben la traza en el registro técnico (`core.logs`, con los números ya enmascarados) y `faulthandler` cubre los fallos de C (GTK, Poppler) en un archivo junto al registro.
2. Si el arranque anterior terminó con un fallo, berigna lo dice una vez: "berigna se cerró de forma inesperada la última vez", con "Copiar informe" (el mismo formato que el informe de diagnóstico: versión, sistema, lector, traza; sin PIN, sin contenido de documentos, con el DNI enmascarado) y el enlace a las incidencias.
3. La persona decide si lo envía y por dónde. Nada sale solo.

Implementado el 2026-10-29 (Fase 4, incremento 1) en `core.crashes`. Como las excepciones de las retrollamadas de GTK no cierran el programa, el aviso dice "berigna tuvo un fallo inesperado la última vez" en lugar de "se cerró". El informe lleva la versión, el sistema y la traza; no lleva el lector, que no forma parte de un fallo.

## 6. Versión candidata para la prueba de usabilidad

La prueba (BRG-CAL-005) durará unas cuatro semanas, en paralelo con la Fase 4. Los participantes deben probar siempre la misma versión, no la rama `main` en movimiento: se etiqueta `v0.3.0-rc.1` al empezar la prueba y BRG-CAL-005 §3.1 instala esa etiqueta. Las correcciones de gravedad 3 y 4 que salgan de la prueba van a `main` y, si hace falta repetir alguna tarea, a una `v0.3.0-rc.2`. Al cerrar la Fase 3 se etiqueta `v0.3.0`.

## 7. Lo que no se recomienda

- Telemetría o informes de fallos remotos (§5).
- Más contenedores o Docker Compose en la CI: el contenedor Debian 13 ya es el entorno de destino.
- Subir el umbral de cobertura del 80 %: el núcleo está al 100 % y la interfaz por encima del 78 %; el valor está en las pruebas por propiedades (R-DES-07), no en el porcentaje.
- Archivos de bloqueo de PyPI para el entorno (`uv lock`, `pip-tools`): las versiones exactas de la CI y los paquetes de Debian ya cumplen ese papel (§1).
