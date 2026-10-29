# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Prototipo de investigación (spike). No es código de producción.
"""SPK-01 §9: prueba de firma con PIN sobre el DNIe v2 (berigna).

Qué hace (y nada más):
  1. Lee el certificado de firma (sin PIN).
  2. Pide confirmación y el PIN, que se envía UNA sola vez (sin reintentos).
  3. Firma el SHA-256 de un texto de prueba (no es un documento) y verifica la firma
     con la clave pública del certificado.
  4. Sin volver a enviar el PIN, comprueba si la autenticación persiste:
     (a) una segunda firma directa, (b) MSE + firma, (c) tras volver a seleccionar el applet.
  5. Mide tiempos y guarda un informe en el directorio indicado.

Instrucciones permitidas: SELECT, READ BINARY, VERIFY, MSE:SET, PSO:CDS. Nada más.
"""
import getpass
import hashlib
import json
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from smartcard.System import readers

PKI_AID = list(bytes.fromhex("E828BD080FD250") + b"Generic")
SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
ALLOWED_INS = {0xA4, 0xB1, 0x20, 0x22, 0x2A}
MSE_SET_SIGN = [0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x8A, 0x84, 0x01, 0x81]
PIN_REF_SIGNATURE = 0x81
DNIE_V2_ATR = "3BDC18FF8191FE1FC38073C821136605036351000250"

out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
out_dir.mkdir(parents=True, exist_ok=True)
report: dict = {"steps": []}


def log(step: str, **kv) -> None:
    report["steps"].append({"step": step, **kv})
    print(f"  · {step}: " + ", ".join(f"{k}={v}" for k, v in kv.items()))


conn = None
for r in readers():
    c = r.createConnection()
    try:
        c.connect()
    except Exception:  # noqa: BLE001
        continue
    if bytes(c.getATR()).hex().upper() == DNIE_V2_ATR:
        conn = c
        report["reader"] = str(r)
        break
if conn is None:
    sys.exit("No se encontró un DNIe v2 en ningún lector.")
print(f"Lector: {report['reader']}")


def tx(apdu: list[int]) -> tuple[bytes, int, int, float]:
    assert apdu[1] in ALLOWED_INS, "instrucción no permitida"
    t0 = time.perf_counter()
    data, sw1, sw2 = conn.transmit(apdu)
    return bytes(data), sw1, sw2, (time.perf_counter() - t0) * 1000


def select_pki() -> str:
    _, sw1, sw2, _ = tx([0x00, 0xA4, 0x04, 0x00, len(PKI_AID), *PKI_AID])
    return f"{sw1:02X}{sw2:02X}"


def read_sign_cert() -> bytes:
    select_pki()
    tx([0x00, 0xA4, 0x02, 0x04, 0x02, 0x00, 0x1D])
    buf, off, total = b"", 0, None
    while total is None or len(buf) < total:
        d, sw1, sw2, _ = tx([0x00, 0xB1, 0x00, 0x00, 0x04, 0x54, 0x02, off >> 8, off & 0xFF, 0xFF])
        buf += d[3:]
        if total is None and len(buf) >= 4:
            total = 4 + int.from_bytes(buf[2:4], "big")
        if (sw1, sw2) != (0x90, 0x00):
            break
        off += 0xE4
    return buf[:total]


def pso_cds(digest: bytes) -> tuple[bytes, str, float]:
    payload = list(SHA256_DIGESTINFO_PREFIX + digest)
    d, sw1, sw2, ms = tx([0x00, 0x2A, 0x9E, 0x9A, len(payload), *payload])
    return d, f"{sw1:02X}{sw2:02X}", ms


def verify_sig(pub, sig: bytes, msg: bytes) -> bool:
    try:
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# 1. Certificado (sin PIN)
t0 = time.perf_counter()
cert_der = read_sign_cert()
cert = x509.load_der_x509_certificate(cert_der)
pub = cert.public_key()
log("certificado_firma", bytes=len(cert_der),
    ms=round((time.perf_counter() - t0) * 1000),
    key_usage_non_repudiation=cert.extensions.get_extension_for_class(x509.KeyUsage).value.content_commitment)

# 2. Confirmación y PIN (un solo intento)
print("\nSe va a firmar un TEXTO DE PRUEBA (no un documento) con tu certificado de firma.")
print("El PIN se enviará UNA sola vez. Si es incorrecto, el script se detiene sin reintentar.")
if not sys.stdin.isatty():
    sys.exit("Este script necesita una terminal interactiva (ejecútalo en tu propia terminal). No se envió el PIN.")
if input("¿Continuar? [s/N] ").strip().lower() != "s":
    sys.exit("Cancelado por el usuario. No se envió el PIN.")
pin = bytearray(getpass.getpass("PIN de firma del DNIe: ").encode("ascii"))
if not pin:
    sys.exit("PIN vacío. No se envió nada.")

select_pki()
apdu = [0x00, 0x20, 0x00, PIN_REF_SIGNATURE, len(pin), *pin]
_, sw1, sw2, ms = tx(apdu)
for i in range(len(pin)):
    pin[i] = 0
for i in range(len(apdu)):
    apdu[i] = 0
del pin, apdu
sw = f"{sw1:02X}{sw2:02X}"
log("verify_pin", sw=sw, ms=round(ms))
if sw != "9000":
    hint = ""
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        hint = f" PIN incorrecto: quedan {sw2 & 0x0F} intentos."
    elif sw in ("6983", "6984"):
        hint = " PIN bloqueado."
    report["result"] = f"VERIFY falló ({sw}).{hint}"
    print("\n" + report["result"] + " No se reintenta.")
    (out_dir / "spk01_informe.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    sys.exit(1)

# 3. Primera firma
msg1 = b"berigna SPK-01 prueba de firma 1 - texto sin valor documental"
_, sw1, sw2, ms = tx(MSE_SET_SIGN)
log("mse_set", sw=f"{sw1:02X}{sw2:02X}", ms=round(ms))
sig1, sw, ms = pso_cds(hashlib.sha256(msg1).digest())
ok1 = verify_sig(pub, sig1, msg1) if sw == "9000" else False
log("firma_1", sw=sw, ms=round(ms), bytes=len(sig1), verificada=ok1)

# 4a. Segunda firma directa, sin VERIFY ni MSE
msg2 = b"berigna SPK-01 prueba de firma 2 - texto sin valor documental"
sig2, sw, ms = pso_cds(hashlib.sha256(msg2).digest())
log("firma_2_sin_verify_sin_mse", sw=sw, ms=round(ms),
    verificada=verify_sig(pub, sig2, msg2) if sw == "9000" else False)

# 4b. MSE + firma, sin VERIFY
msg3 = b"berigna SPK-01 prueba de firma 3 - texto sin valor documental"
tx(MSE_SET_SIGN)
sig3, sw, ms = pso_cds(hashlib.sha256(msg3).digest())
log("firma_3_mse_sin_verify", sw=sw, ms=round(ms),
    verificada=verify_sig(pub, sig3, msg3) if sw == "9000" else False)

# 4c. Re-SELECT del applet + MSE + firma, sin VERIFY
msg4 = b"berigna SPK-01 prueba de firma 4 - texto sin valor documental"
log("reselect_applet", sw=select_pki())
tx(MSE_SET_SIGN)
sig4, sw, ms = pso_cds(hashlib.sha256(msg4).digest())
log("firma_4_tras_reselect_sin_verify", sw=sw, ms=round(ms),
    verificada=verify_sig(pub, sig4, msg4) if sw == "9000" else False)

conn.disconnect()
report["result"] = "firma verificada" if ok1 else "la firma 1 no se pudo verificar"
for name, (m, s) in {"1": (msg1, sig1), "2": (msg2, sig2), "3": (msg3, sig3), "4": (msg4, sig4)}.items():
    (out_dir / f"mensaje{name}.txt").write_bytes(m)
    (out_dir / f"firma{name}.bin").write_bytes(s)
(out_dir / "spk01_informe.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
print(f"\nResultado: {report['result']}. Informe en {out_dir / 'spk01_informe.json'}")
