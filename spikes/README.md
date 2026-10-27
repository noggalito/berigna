# Prototipos de investigación (*spikes*)

Código de la Fase 0 que respalda las conclusiones de `docs/10-investigacion/`. **No es código de producción**: no sigue todavía las convenciones de `docs/08-desarrollo/` ni tiene pruebas. Se conserva como referencia para implementar `berigna.core` y como evidencia para el expediente de acreditación.

## Contenido

| Ruta | Qué es | Documento |
|---|---|---|
| `spk01/read_certs.py` | Lee los 3 certificados del DNIe v2 (solo lectura, sin PIN) | SPK-01 §8.4 |
| `spk01/reader_profile.py`, `spk01/tlv_props.py` | Perfil de un lector: protocolo, funciones PC/SC parte 10, tiempos | SPK-01 §8.5 |
| `spk01/spk01_firma_pin.py` | Prueba de firma con PIN y persistencia del VERIFY | SPK-01 §8.6 |
| `spk01/check_auth_state.py` | Comprueba sin PIN que la tarjeta no quedó autenticada | SPK-01 §8.6 |
| `spk01/pdf_sig_info.py` | Extrae firmante, SubFilter y sello de tiempo de PDF firmados | SPK-03 §5 |
| `spk03/spk03_pki.py` | Genera la PKI de pruebas (raíz, intermedia, firmante, TSA, CRL, AIA) | SPK-03 §2 |
| `spk03/spk03_common.py` | `TokenLike` (interfaz del DNIe v2), `TokenSigner` (pyHanko) y TSA de pruebas | SPK-03 §2 |
| `spk03/spk03_cades.py` | CAdES B-B a B-LTA, con `archive-time-stamp-v3` y `ats-hash-index-v3` propios | SPK-03 §4 |
| `spk03/spk03_xades.py` | XAdES envuelta y envolvente de B-B a B-LTA (signxml más capa propia) | SPK-03 §4 |
| `spk03/spk03_pades.py` | PAdES B-B a B-LTA con pyHanko | SPK-03 §3 |
| `spk03/spk03_dnie.py` | CAdES, XAdES y PAdES B-B con el DNIe real y un solo PIN (driver APDU) | SPK-03 §7 |
| `spk03/dssval/` | Arnés Java mínimo sobre DSS 6.2 (validador de referencia) | SPK-03 §2 |
| `spk03/run_matrix.sh` | Valida con DSS todas las firmas generadas y comprueba cada sello | SPK-03 §3 |
| `spk03/evidencias/matriz-resultados.txt` | Resultado de la matriz: 20 de 20 en TOTAL_PASSED | SPK-03 §3 |
| `ca-iofe/` | Certificados **públicos** de la cadena del DNIe v2 (huellas en `docs/04-arquitectura/configuracion-y-datos.md` §3) | configuracion-y-datos §3 |

No se incluyen, a propósito, los certificados personales del titular, las firmas hechas con su DNIe, los PDF de terceros, los binarios descargados ni las claves de la PKI de pruebas (se regeneran).

## Uso

```sh
sh spikes/preparar-entorno.sh          # una vez; no instala nada en el sistema
. spikes/.entorno/activar
cd spikes/spk03
python3 spk03_pki.py pki
(cd pki && python3 -m http.server 8765 --bind 127.0.0.1 &)   # CRL y AIA de la PKI de pruebas
python3 spk03_cades.py pki out/cades
python3 spk03_xades.py pki out/xades
python3 spk03_pades.py pki out/pades
sh run_matrix.sh
```

Los *scripts* que usan el PIN de un DNIe real (`spk01_firma_pin.py`, `spk03_dnie.py`) deben ejecutarse en la terminal del titular y siguiendo `docs/07-calidad/protocolo-pruebas-con-pin.md`. Por ejemplo:

```sh
python3 spikes/spk03/spk03_dnie.py spikes/ca-iofe /ruta/de/salida
```

## Licencias de terceros

Los prototipos usan, sin redistribuirlos: pyHanko (MIT), signxml (Apache-2.0), cryptography (Apache-2.0/BSD), asn1crypto (MIT), pyscard (LGPL-2.1+), DSS (LGPL-2.1) y Apache Maven (Apache-2.0). El protocolo del *applet* PKI del DNIe v2 se documentó a partir del proyecto [peru-dnie](https://github.com/edeustua/peru-dnie) (MIT); no se copió su código.
