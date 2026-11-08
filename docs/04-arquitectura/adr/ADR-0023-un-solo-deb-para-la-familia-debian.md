# ADR-0023: Un solo `.deb` para la familia Debian

- Estado: Aceptado
- Fecha: 2026-11-08
- Origen: Decisión del titular (2026-11-08) de llevar berigna a Ubuntu 26.04 LTS sin un segundo paquete; complementa [ADR-0006](ADR-0006-distribucion-deb.md) y [ADR-0013](ADR-0013-pyhanko-0-25-empaquetado-debian.md)

## Contexto

ADR-0006 fija el `.deb` para Debian 13 como formato principal de la v1. Ubuntu y sus derivadas comparten el formato, `apt` y casi todas las dependencias de berigna, pero con otras versiones: Ubuntu 26.04 LTS trae Python 3.14, cryptography 46, lxml 6, libadwaita 1.9 y xmlsec1 1.3, frente a Python 3.13, cryptography 43, lxml 5, libadwaita 1.7 y xmlsec1 1.2 de Debian 13.

La práctica habitual sería compilar un paquete por distribución (`0.3.0-1~deb13`, `0.3.0-1~ubuntu26.04`). Para berigna eso no hace falta, y además tiene un costo:

- Los paquetes del proyecto (`berigna`, `berigna-nautilus` y `python3-pyhanko`) son `Architecture: all`, en Python puro y sin extensiones compiladas. `dh_python3` no pone techo a la versión de Python (`python3 (>= 3.12)`) y la compilación a *bytecode* se hace al instalar, con el Python de cada sistema.
- Cada paquete adicional es otro artefacto con otro SHA-256: hay que compilarlo, firmarlo, publicarlo, describirlo en la documentación y responder por él.
- Las diferencias de versión se notan al ejecutar, no al compilar. Por eso se encuentran y se corrigen en el código, que debe funcionar con todo el rango de versiones, como ya se hace con pyhanko-certvalidator (R-15).

Comprobado el 2026-11-08: los `.deb` compilados en Debian 13, sin recompilar, se instalan en Ubuntu 26.04 y pasan la suite completa contra el paquete instalado. La comprobación encontró un fallo real del núcleo (`InvalidVersion` de cryptography) y dos pruebas que dependían de las versiones de Debian 13. Las tres cosas se corrigieron sin un segundo paquete (BRG-DSP-001 §5 bis).

## Decisión

1. **Un entregable por formato.** Los `.deb` se compilan una sola vez, en Debian 13, la base más antigua de la familia soportada. Ese mismo artefacto, con el mismo SHA-256, se instala en cada distribución soportada. No hay paquetes por distribución ni sufijos de versión por distribución.
2. **La matriz de pruebas define las distribuciones soportadas.** Una distribución está soportada cuando la CI instala en ella los `.deb` de Debian 13 y la suite completa pasa contra el paquete instalado (`scripts/probar-paquete-instalado.sh`), y cuando además pasa la prueba en un sistema real con el DNIe. La vigilancia semanal repite la prueba con las actualizaciones de cada distribución. Para quitar una distribución basta con sacarla de la matriz, no hay que dejar de publicar nada.
3. **El `Depends` declara los mínimos reales.** Los límites de versión de `pyproject.toml` se repiten en el `Depends` de `debian/control`, y `scripts/verificar-dependencias.py` comprueba en la CI que coinciden. Así, `apt` rechaza, con un mensaje claro, una distribución que no los cumple, en vez de instalar un berigna que falle al firmar. La CI comprueba ese rechazo en Ubuntu 24.04 LTS (`scripts/probar-rechazo.sh`).
4. **Las diferencias de versión se resuelven en el código**, compatible con todo el rango, nunca con un paquete distinto ni con parches por distribución.

Distribuciones: Debian 13 y, según la decisión del titular del 2026-11-08, Ubuntu 26.04 LTS desde la v1.0 (RNF-COM-07). LMDE 7 y Linux Mint 23 pueden entrar sin trabajo de empaquetado cuando se agreguen a la matriz. Ubuntu 24.04 LTS y Linux Mint 22 quedan fuera: no traen signxml, y sus versiones de cryptography y pyscard están por debajo de los mínimos.

## Alternativas consideradas

- **Un paquete por distribución, compilado en cada una.** Se descarta: multiplica los artefactos sin ninguna ventaja técnica para paquetes `Architecture: all`, y deja sin resolver lo importante, que son las diferencias al ejecutar.
- **Bajar los mínimos para incluir Ubuntu 24.04.** Se descarta: obligaría a empaquetar signxml y a sostener versiones de cryptography y pyscard que el proyecto no prueba con el DNIe.
- **Flatpak para Ubuntu desde la v1.0.** Se mantiene en la 1.1 (ADR-0006) para las distribuciones que el `.deb` no cubre, con el mismo principio de un entregable por formato.

## Consecuencias

- El repositorio APT tiene una sola suite para toda la familia, con el mismo `.sources` y la misma clave en todas las distribuciones. Las instrucciones de instalación son idénticas.
- La CI compila los paquetes una vez (`scripts/compilar-paquetes.sh`) y los prueba en Ubuntu 26.04 y en Ubuntu 24.04, para comprobar el rechazo. Ubuntu 26.04 pasa a ser una comprobación obligatoria en la Fase 6.
- La compatibilidad tiene un límite: cuando una versión nueva de una biblioteca en alguna distribución ya no quepa en el mismo código, habrá que retirar esa distribución de la matriz o subir el mínimo para todas. Esa decisión se toma en la vigilancia semanal, antes de que el problema llegue a los usuarios.
- Algunas bibliotecas anuncian cambios que todavía no rompen nada. Por ejemplo, cryptography 46 avisa de que dejará de leer certificados con número de serie 0, y la TSL de INDECOPI trae tres raíces extranjeras así. Una prueba fija que hoy se conservan, de modo que el día que la biblioteca las rechace la prueba falle y la decisión de descartarlas sea explícita (BRG-DSP-001 §5 bis).
