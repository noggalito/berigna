# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
# Prototipo de investigación (spike). No es código de producción.
"""SPK-03: XAdES enveloped B-B / B-T / B-LT with signxml 4.0.5 (Debian 13) + own code for unsigned properties.

The private-key operation is delegated to TokenLike (digest in, signature out), like the DNIe v2 driver.
"""
import asyncio
import base64
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from lxml import etree
from signxml import methods
from signxml.xades import XAdESSigner

from spk03_common import TokenLike, test_tsa

PKI, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
DS = "http://www.w3.org/2000/09/xmldsig#"
XADES = "http://uri.etsi.org/01903/v1.3.2#"
XADES141 = "http://uri.etsi.org/01903/v1.4.1#"
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
# References without Transforms are canonicalised with C14N 1.0 (XMLDSig); using it for SignedInfo too keeps
# signxml and validators (DSS/Santuario) in agreement.
C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
NS = {"ds": DS, "xades": XADES}

token = TokenLike((PKI / "signer.key.der").read_bytes())
tsa = test_tsa(PKI)
pem = lambda n: (PKI / f"{n}.pem").read_text()  # noqa: E731
der = lambda n: base64.b64decode("".join(pem(n).strip().splitlines()[1:-1]))  # noqa: E731


class TokenKey:
    """Duck-typed RSA private key for signxml: hashes locally, signs the digest in the 'token'."""

    def __init__(self, tok, public_key):
        self.tok, self._pub = tok, public_key

    def sign(self, data, padding, algorithm):
        assert isinstance(algorithm, hashes.SHA256)
        return self.tok.sign_digest(hashlib.sha256(data).digest())

    def public_key(self):
        return self._pub


def make_doc() -> etree._Element:
    root = etree.Element("DeclaracionJurada")
    etree.SubElement(root, "Titular").text = "PRUEBA FIRMANTE"
    etree.SubElement(root, "Texto").text = "Documento XML de prueba SPK-03 berigna"
    return root


def c14n(el, exclusive=True) -> bytes:
    return etree.tostring(el, method="c14n", exclusive=exclusive)


def unsigned_props(sig: etree._Element) -> etree._Element:
    qp = sig.find(".//xades:QualifyingProperties", NS)
    up = qp.find("xades:UnsignedProperties", NS)
    if up is None:
        up = etree.SubElement(qp, f"{{{XADES}}}UnsignedProperties")
    usp = up.find("xades:UnsignedSignatureProperties", NS)
    if usp is None:
        usp = etree.SubElement(up, f"{{{XADES}}}UnsignedSignatureProperties")
    return usp


def timestamp_der(data: bytes) -> bytes:
    tst = asyncio.run(tsa.async_timestamp(hashlib.sha256(data).digest(), "sha256"))
    return tst.dump()


def add_signature_timestamp(sig):
    sv = sig.find("ds:SignatureValue", NS)
    usp = unsigned_props(sig)
    ts = etree.SubElement(usp, f"{{{XADES}}}SignatureTimeStamp", Id="sigts")
    etree.SubElement(ts, f"{{{DS}}}CanonicalizationMethod", Algorithm=EXC_C14N)
    etree.SubElement(ts, f"{{{XADES}}}EncapsulatedTimeStamp").text = base64.b64encode(
        timestamp_der(c14n(sv))).decode()


def add_lt_values(sig):
    usp = unsigned_props(sig)
    cv = etree.SubElement(usp, f"{{{XADES}}}CertificateValues")
    for n in ("signer", "int", "root", "tsa"):
        etree.SubElement(cv, f"{{{XADES}}}EncapsulatedX509Certificate").text = base64.b64encode(der(n)).decode()
    rv = etree.SubElement(usp, f"{{{XADES}}}RevocationValues")
    crlv = etree.SubElement(rv, f"{{{XADES}}}CRLValues")
    for n in ("int", "root"):
        etree.SubElement(crlv, f"{{{XADES}}}EncapsulatedCRLValue").text = base64.b64encode(
            (PKI / f"{n}.crl").read_bytes()).decode()


def reference_octets(doc_root, sig, ref) -> bytes:
    """Octets of one ds:Reference as used for ArchiveTimeStamp (EN 319 132-1 / DSS 8.2.1, step 2)."""
    import copy
    uri = ref.get("URI")
    transforms = [t.get("Algorithm") for t in ref.findall("ds:Transforms/ds:Transform", NS)]
    if uri == "":
        tmp = copy.deepcopy(doc_root)
        for s in tmp.findall(".//ds:Signature", NS):
            s.getparent().remove(s)
        exclusive = EXC_C14N in transforms
        return etree.tostring(tmp, method="c14n", exclusive=exclusive)
    target = sig.getroottree().getroot().xpath(f"//*[@Id='{uri[1:]}']")[0]
    return etree.tostring(target, method="c14n", exclusive=False)  # node-set -> archive c14n (C14N 1.0)


def add_archive_timestamp(doc_root, sig):
    h = hashlib.sha256()
    for ref in sig.findall("ds:SignedInfo/ds:Reference", NS):
        octets = reference_octets(doc_root, sig, ref)
        assert base64.b64encode(hashlib.sha256(octets).digest()).decode() == ref.find("ds:DigestValue", NS).text, \
            f"reconstrucción de la referencia {ref.get('URI')!r} no coincide con DigestValue"
        h.update(octets)
    for path in ("ds:SignedInfo", "ds:SignatureValue", "ds:KeyInfo"):
        el = sig.find(path, NS)
        if el is not None:
            h.update(c14n(el, exclusive=False))
    usp = unsigned_props(sig)
    for prop in usp:
        h.update(c14n(prop, exclusive=False))
    # xades141:ArchiveTimeStamp covers every ds:Object except the QualifyingProperties one, referenced or not
    # (excluding referenced objects only applies to the legacy XAdES 1.3.2 ArchiveTimeStamp).
    for obj in sig.findall("ds:Object", NS):
        if obj.find("xades:QualifyingProperties", NS) is None:
            h.update(c14n(obj, exclusive=False))
    tst = asyncio.run(tsa.async_timestamp(h.digest(), "sha256")).dump()
    ats = etree.SubElement(usp, f"{{{XADES141}}}ArchiveTimeStamp", Id="archts")
    etree.SubElement(ats, f"{{{DS}}}CanonicalizationMethod", Algorithm=C14N10)
    etree.SubElement(ats, f"{{{XADES}}}EncapsulatedTimeStamp").text = base64.b64encode(tst).decode()


def sign(level: str, method=methods.enveloped) -> etree._Element:
    from cryptography import x509
    signer_x509 = x509.load_pem_x509_certificate(pem("signer").encode())
    s = XAdESSigner(method=method, signature_algorithm="rsa-sha256",
                    digest_algorithm="sha256", c14n_algorithm=C14N10)
    signed = s.sign(make_doc(), key=TokenKey(token, signer_x509.public_key()),
                    cert=[pem("signer")])
    sig = signed if signed.tag == f"{{{DS}}}Signature" else signed.find(".//ds:Signature", NS)
    if level in ("B-T", "B-LT", "B-LTA"):
        add_signature_timestamp(sig)
    if level in ("B-LT", "B-LTA"):
        add_lt_values(sig)
    if level == "B-LTA":
        add_archive_timestamp(signed, sig)
    return signed


for level in ("B-B", "B-T", "B-LT", "B-LTA"):
    doc = sign(level)
    (OUT / f"xades-{level}.xml").write_bytes(etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
for level in ("B-B", "B-T", "B-LT", "B-LTA"):
    doc = sign(level, methods.enveloping)
    (OUT / f"xades-enveloping-{level}.xml").write_bytes(etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
print(f"XAdES generadas en {OUT}; operaciones en el 'token': {token.calls}")
