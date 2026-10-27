# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
# Prototipo de investigación (spike). No es código de producción.
"""SPK-03 final: CAdES, XAdES and PAdES B-B with the real DNIe v2 in ONE PIN session.

Follows docs/07-calidad/protocolo-pruebas-con-pin.md:
  - PIN typed by the holder only, sent once (no retries), explicit [s/N] confirmation before.
  - Exclusive PC/SC connection; the card is powered off at the end (SCARD_UNPOWER_CARD), also on errors.
  - Allowed instructions: SELECT, READ BINARY, VERIFY, MSE:SET, PSO:CDS.
Signs TEST CONTENT only (a text file, a small XML and a one-page PDF created here).
"""
import asyncio
import base64
import getpass
import hashlib
import io
import sys
import time
from pathlib import Path

from asn1crypto import x509 as ax509, pem as apem
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from lxml import etree
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from signxml import methods
from signxml.xades import XAdESSigner
from smartcard.scard import SCARD_SHARE_EXCLUSIVE, SCARD_UNPOWER_CARD
from smartcard.System import readers

from spk03_common import TokenSigner
from spk03_pades import minimal_pdf

CERTS, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
DNIE_V2_ATR = "3BDC18FF8191FE1FC38073C821136605036351000250"
PKI_AID = list(bytes.fromhex("E828BD080FD250") + b"Generic")
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
ALLOWED_INS = {0xA4, 0xB1, 0x20, 0x22, 0x2A}
C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"


class DnieV2:
    def __init__(self):
        self.conn = None
        for r in readers():
            c = r.createConnection()
            try:
                c.connect(mode=SCARD_SHARE_EXCLUSIVE, disposition=SCARD_UNPOWER_CARD)
            except Exception:  # noqa: BLE001
                continue
            if bytes(c.getATR()).hex().upper() == DNIE_V2_ATR:
                self.conn, self.reader = c, str(r)
                break
            c.disconnect()
        if self.conn is None:
            sys.exit("No se encontró un DNIe v2 (o la tarjeta está en uso por otro programa).")
        self.calls, self.times = 0, []

    def tx(self, apdu):
        assert apdu[1] in ALLOWED_INS, "instrucción no permitida"
        data, sw1, sw2 = self.conn.transmit(apdu)
        return bytes(data), f"{sw1:02X}{sw2:02X}"

    def select(self):
        return self.tx([0x00, 0xA4, 0x04, 0x00, len(PKI_AID), *PKI_AID])[1]

    def read_sign_cert(self) -> bytes:
        self.select()
        self.tx([0x00, 0xA4, 0x02, 0x04, 0x02, 0x00, 0x1D])
        buf, off, total = b"", 0, None
        while total is None or len(buf) < total:
            d, sw = self.tx([0x00, 0xB1, 0x00, 0x00, 0x04, 0x54, 0x02, off >> 8, off & 0xFF, 0xFF])
            buf += d[3:]
            if total is None and len(buf) >= 4:
                total = 4 + int.from_bytes(buf[2:4], "big")
            if sw != "9000":
                break
            off += 0xE4
        return buf[:total]

    def verify_pin_once(self) -> str:
        pin = bytearray(getpass.getpass("PIN de firma del DNIe: ").encode("ascii"))
        if not pin:
            return "vacío"
        self.select()
        apdu = [0x00, 0x20, 0x00, 0x81, len(pin), *pin]
        _, sw = self.tx(apdu)
        for i in range(len(pin)):
            pin[i] = 0
        for i in range(len(apdu)):
            apdu[i] = 0
        return sw

    def sign_digest(self, digest: bytes) -> bytes:
        assert len(digest) == 32
        self.tx([0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x8A, 0x84, 0x01, 0x81])
        payload = list(SHA256_PREFIX + digest)
        t0 = time.perf_counter()
        sig, sw = self.tx([0x00, 0x2A, 0x9E, 0x9A, len(payload), *payload])
        self.times.append(round((time.perf_counter() - t0) * 1000))
        if sw != "9000":
            raise RuntimeError(f"PSO:CDS falló: {sw}")
        self.calls += 1
        return sig

    def close(self):
        if self.conn is not None:
            self.conn.disconnect()  # disposition = SCARD_UNPOWER_CARD -> ends the security session
            self.conn = None


class TokenKey:
    def __init__(self, tok, public_key):
        self.tok, self._pub = tok, public_key

    def sign(self, data, padding, algorithm):
        assert isinstance(algorithm, hashes.SHA256)
        return self.tok.sign_digest(hashlib.sha256(data).digest())

    def public_key(self):
        return self._pub


def load_pem(path):
    _, _, der = apem.unarmor(Path(path).read_bytes())
    return ax509.Certificate.load(der)


card = DnieV2()
print(f"Lector: {card.reader} (conexión exclusiva)")
try:
    cert_der = card.read_sign_cert()
    cert_crypto = x509.load_der_x509_certificate(cert_der)
    assert cert_crypto.extensions.get_extension_for_class(x509.KeyUsage).value.content_commitment
    cert_asn1 = ax509.Certificate.load(cert_der)
    chain = [load_pem(CERTS / "ecep-reniec-ca-class-2-ii.pem"), load_pem(CERTS / "ecep-reniec.pem"),
             load_pem(CERTS / "ecernep-peru-ca-root-3.pem")]
    print("Certificado de firma leído (no repudio).")
    print("\nSe firmarán 3 ARCHIVOS DE PRUEBA creados por este script (texto, XML y PDF), nivel B-B.")
    print("El PIN se enviará UNA sola vez. Si es incorrecto, el script se detiene sin reintentar.")
    if not sys.stdin.isatty():
        sys.exit("Necesita una terminal interactiva. No se envió el PIN.")
    if input("¿Continuar? [s/N] ").strip().lower() != "s":
        sys.exit("Cancelado. No se envió el PIN.")
    sw = card.verify_pin_once()
    print(f"  · VERIFY: {sw}")
    if sw != "9000":
        extra = f" Quedan {int(sw[3], 16)} intentos." if sw.startswith("63C") else ""
        sys.exit(f"PIN no aceptado ({sw}).{extra} No se reintenta.")

    # CAdES B-B (detached)
    data = "Archivo de prueba SPK-03 firmado con DNIe v2 (berigna)\n".encode()
    (OUT / "dnie-datos.txt").write_bytes(data)
    signer = TokenSigner(card, cert_asn1, chain)
    ci = asyncio.run(signer.async_sign_general_data(data, "sha256", detached=True, use_cades=True))
    (OUT / "dnie-cades-B-B.p7s").write_bytes(ci.dump())
    print("  · CAdES B-B: hecha")

    # XAdES B-B (enveloped)
    root = etree.Element("PruebaBerigna")
    etree.SubElement(root, "Texto").text = "XML de prueba SPK-03 firmado con DNIe v2"
    pem_cert = "-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(cert_der).decode() + "-----END CERTIFICATE-----\n"
    xs = XAdESSigner(method=methods.enveloped, signature_algorithm="rsa-sha256",
                     digest_algorithm="sha256", c14n_algorithm=C14N10)
    signed = xs.sign(root, key=TokenKey(card, cert_crypto.public_key()), cert=[pem_cert])
    (OUT / "dnie-xades-B-B.xml").write_bytes(etree.tostring(signed, xml_declaration=True, encoding="UTF-8"))
    print("  · XAdES B-B: hecha")

    # PAdES B-B
    meta = signers.PdfSignatureMetadata(field_name="FirmaBerigna", md_algorithm="sha256",
                                        subfilter=SigSeedSubFilter.PADES, reason="Prueba SPK-03 berigna",
                                        location="Peru")
    pdf = signers.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(minimal_pdf())), meta, signer=signer)
    (OUT / "dnie-pades-B-B.pdf").write_bytes(pdf.getvalue())
    print("  · PAdES B-B: hecha")
    print(f"\nFirmas en el chip: {card.calls} con un solo PIN; tiempos PSO:CDS (ms): {card.times}")
finally:
    card.close()
    print("Sesión cerrada (tarjeta apagada).")
