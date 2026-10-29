# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Prototipo de investigación (spike). No es código de producción.
"""SPK-03: test PKI imitating the IOFE hierarchy (root -> intermediate -> signer, root -> TSA).

CRLs are published at http://127.0.0.1:8765/<name>.crl (served by a local http.server).
"""
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
NOW = dt.datetime.now(dt.timezone.utc)
BASE = "http://127.0.0.1:8765"


def name(cn, o="Berigna Test PKI"):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def cert(subject, skey, issuer, ikey, *, ca, pathlen=None, ku, eku=None, crl=None, aia=None, days=730):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(skey.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
         .add_extension(ku, critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(skey.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    if aia:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(f"{BASE}/{aia}.cer"))]), critical=False)
    if crl:
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            [x509.UniformResourceIdentifier(f"{BASE}/{crl}.crl")], None, None, None)]), critical=False)
    return b.sign(ikey, hashes.SHA256())


def ku(**kw):
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False)
    base.update(kw)
    return x509.KeyUsage(**base)


root_k, int_k, sig_k, tsa_k = key(), key(), key(), key()
root = cert(name("TEST ECERNEP ROOT"), root_k, name("TEST ECERNEP ROOT"), root_k, ca=True, pathlen=2,
            ku=ku(key_cert_sign=True, crl_sign=True), days=3650)
inter = cert(name("TEST ECEP-RENIEC CA Class 2"), int_k, root.subject, root_k, ca=True, pathlen=0,
             ku=ku(key_cert_sign=True, crl_sign=True), crl="root", aia="root")
signer = cert(name("PRUEBA FIRMANTE FIR 00000000 hard", "Berigna Test PKI"), sig_k, inter.subject, int_k,
              ca=False, ku=ku(content_commitment=True), crl="int", aia="int")
tsa = cert(name("TEST TSA"), tsa_k, root.subject, root_k, ca=False, ku=ku(digital_signature=True),
           eku=[ExtendedKeyUsageOID.TIME_STAMPING], crl="root", aia="root")


def crl(issuer_cert, ikey, fname):
    c = (x509.CertificateRevocationListBuilder().issuer_name(issuer_cert.subject)
         .last_update(NOW - dt.timedelta(hours=1)).next_update(NOW + dt.timedelta(days=7))
         .add_extension(x509.CRLNumber(1), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False)
         .sign(ikey, hashes.SHA256()))
    (OUT / f"{fname}.crl").write_bytes(c.public_bytes(serialization.Encoding.DER))


crl(root, root_k, "root")
crl(inter, int_k, "int")
for n, c in {"root": root, "int": inter, "signer": signer, "tsa": tsa}.items():
    (OUT / f"{n}.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    (OUT / f"{n}.cer").write_bytes(c.public_bytes(serialization.Encoding.DER))
for n, k in {"signer": sig_k, "tsa": tsa_k}.items():
    (OUT / f"{n}.key.der").write_bytes(k.private_bytes(serialization.Encoding.DER,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
print("PKI de pruebas creada en", OUT)
