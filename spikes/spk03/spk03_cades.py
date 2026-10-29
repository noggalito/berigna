# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
# Prototipo de investigación (spike). No es código de producción.
"""SPK-03: CAdES B-B / B-T / B-LT / B-LTA (detached .p7s and enveloping .p7m) with pyHanko 0.25.1.

B-B and B-T: pyHanko (use_cades=True + timestamper).
B-LT: own code adds chain certificates + CRLs to SignedData.certificates / crls.
B-LTA: own code adds archive-time-stamp-v3 with ats-hash-index-v3 (EN 319 122-1 §5.5.3).
"""
import asyncio
import hashlib
import sys
from pathlib import Path

from asn1crypto import algos, cms, core, crl as acrl

from spk03_common import TokenLike, TokenSigner, load_cert, test_tsa

PKI, OUT = Path(sys.argv[1]), Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
DATA = "Documento de prueba SPK-03 berigna (CAdES)\n".encode() * 50
(OUT / "datos.txt").write_bytes(DATA)

root, inter, signer_cert, tsa_cert = (load_cert(PKI / f"{n}.pem") for n in ("root", "int", "signer", "tsa"))
token = TokenLike((PKI / "signer.key.der").read_bytes())
signer = TokenSigner(token, signer_cert, [inter, root])
tsa = test_tsa(PKI)
CRLS = [acrl.CertificateList.load((PKI / f"{n}.crl").read_bytes()) for n in ("int", "root")]


# ---- ats-hash-index-v3 (0.4.0.19122.1.5) -------------------------------------------------
class OctetStrings(core.SequenceOf):
    _child_spec = core.OctetString


class ATSHashIndexV3(core.Sequence):
    _fields = [
        # Encoded explicitly (not as DER DEFAULT): DSS/BouncyCastle recompose the index with it present.
        ("hash_ind_algorithm", algos.DigestAlgorithm),
        ("certificates_hash_index", OctetStrings),
        ("crls_hash_index", OctetStrings),
        ("unsigned_attr_values_hash_index", OctetStrings),
    ]


OID_ATS_HASH_INDEX_V3 = "0.4.0.19122.1.5"
OID_ARCHIVE_TS_V3 = "0.4.0.1733.2.4"
H = lambda b: hashlib.sha256(b).digest()  # noqa: E731


def add_lt_data(ci: cms.ContentInfo) -> cms.ContentInfo:
    sd = ci["content"]
    have = {c.chosen.dump() for c in sd["certificates"]} if sd["certificates"].native else set()
    certs = list(sd["certificates"]) if sd["certificates"].native else []
    for c in (signer_cert, inter, root, tsa_cert):
        if c.dump() not in have:
            certs.append(cms.CertificateChoices(name="certificate", value=c))
    sd["certificates"] = cms.CertificateSet(certs)
    sd["crls"] = cms.RevocationInfoChoices([cms.RevocationInfoChoice(name="crl", value=c) for c in CRLS])
    return cms.ContentInfo.load(ci.dump(force=True))


async def add_archive_ts_v3(ci: cms.ContentInfo, detached_data: bytes | None) -> cms.ContentInfo:
    sd = ci["content"]
    si = sd["signer_infos"][0]
    unsigned = list(si["unsigned_attrs"]) if si["unsigned_attrs"].native else []
    idx = ATSHashIndexV3({
        "hash_ind_algorithm": {"algorithm": "sha256"},
        "certificates_hash_index": [H(c.dump()) for c in sd["certificates"]],
        "crls_hash_index": [H(c.dump()) for c in sd["crls"]],
        "unsigned_attr_values_hash_index": [
            H(a["type"].dump() + v.dump()) for a in unsigned for v in a["values"]],
    })
    econtent = sd["encap_content_info"]["content"]
    content_octets = detached_data if detached_data is not None else econtent.native
    fields = b"".join(si[f].dump() for f in
                      ("version", "sid", "digest_algorithm", "signed_attrs", "signature_algorithm", "signature"))
    # EN 319 122-1 §5.5.3: eContentType || H(signed data) || SignerInfo fields || ATSHashIndexV3
    imprint_input = sd["encap_content_info"]["content_type"].dump() + H(content_octets) + fields + idx.dump()
    tst = await tsa.async_timestamp(H(imprint_input), "sha256")
    tsi = tst["content"]["signer_infos"][0]
    tsi["unsigned_attrs"] = cms.CMSAttributes([cms.CMSAttribute({
        "type": cms.CMSAttributeType(OID_ATS_HASH_INDEX_V3), "values": [idx]})])
    tst = cms.ContentInfo.load(tst.dump(force=True))
    unsigned.append(cms.CMSAttribute({"type": cms.CMSAttributeType(OID_ARCHIVE_TS_V3), "values": [tst]}))
    si["unsigned_attrs"] = cms.CMSAttributes(unsigned)
    return cms.ContentInfo.load(ci.dump(force=True))


async def make(level: str, detached: bool) -> cms.ContentInfo:
    ci = await signer.async_sign_general_data(
        DATA, "sha256", detached=detached, use_cades=True,
        timestamper=tsa if level != "B-B" else None)
    if level in ("B-LT", "B-LTA"):
        ci = add_lt_data(ci)
    if level == "B-LTA":
        ci = await add_archive_ts_v3(ci, DATA if detached else None)
    return ci


for level in ("B-B", "B-T", "B-LT", "B-LTA"):
    for detached, ext in ((True, "p7s"), (False, "p7m")):
        ci = asyncio.run(make(level, detached))
        (OUT / f"cades-{level}.{ext}").write_bytes(ci.dump())
print(f"CAdES generadas en {OUT}; operaciones en el 'token': {token.calls}")
