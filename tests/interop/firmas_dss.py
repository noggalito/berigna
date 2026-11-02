# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""XAdES signed by DSS 6.2, verified by berigna and by DSS (PR-INT-06, BRG-CAL-006 §3.5).

DSS signs one test XML document per packaging (enveloped, enveloping, detached) and level
(B-B to B-LTA) with a key of the test PKI (``brg.Sign`` of the SPK-03 harness), a test TSA
served over HTTP and the revocation data of the test PKI as files. Then each signature is
verified offline by berigna's ``verify_xades`` and validated by DSS (``brg.Validate``), and
the table compares both indications: PR-INT-06 asks for the same result.

    .venv/bin/python tests/interop/firmas_dss.py /tmp/firmas-dss [spikes/spk03/dssval]
"""

import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from berigna.core.validation.xades import verify_xades
from support.pki import build_pki
from support.tsa import local_tsa, make_timestamper

CONTENT = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b"<Declaracion><Texto>Documento XML de prueba firmado por DSS (PR-INT-06)</Texto>"
    b"</Declaracion>"
)
PACKAGINGS = {"ENVELOPED": "envuelta", "ENVELOPING": "envolvente", "DETACHED": "separada"}
LEVELS = ("B", "T", "LT", "LTA")


def _pem(path: Path, certificate: x509.Certificate) -> str:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return str(path)


def _java(dssval: Path, main: str, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed program, arguments from this script
        ["java", "-cp", "classes:lib/*", f"brg.{main}", *args],  # noqa: S607
        cwd=dssval,
        capture_output=True,
        text=True,
        check=False,
    )
    if main == "Sign" and result.returncode != 0:
        raise RuntimeError(result.stderr[-2000:])
    return result.stdout


def main(out: Path, dssval: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    pki = build_pki()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.leaf("FIRMANTE DSS", key=leaf_key)
    (out / "firmante.pk8").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    chain = ",".join(
        (
            _pem(out / "firmante.pem", leaf),
            _pem(out / "ca.pem", pki.ca),
            _pem(out / "raiz-pruebas.pem", pki.root),
        )
    )
    stamper, tsa = make_timestamper(pki)
    revocation = {
        "arl.crl": pki.arl(),
        "firmante-ocsp.der": pki.ocsp(leaf),
        "tsa-ocsp.der": pki.ocsp(tsa),
    }
    for name, der in revocation.items():
        (out / name).write_bytes(der)
    revocation_files = ",".join(str(out / name) for name in revocation)
    document = out / "datos.xml"
    document.write_bytes(CONTENT)

    print("| Archivo | berigna | DSS 6.2 |")
    print("|---|---|---|")
    with local_tsa(stamper) as url:
        for packaging, spanish in PACKAGINGS.items():
            for level in LEVELS:
                name = f"dss-xades-{spanish}-B-{level}.xml"
                signed = out / name
                _java(
                    dssval,
                    "Sign",
                    str(document),
                    packaging,
                    level,
                    str(out / "firmante.pk8"),
                    chain,
                    str(signed),
                    "" if level == "B" else url,
                    revocation_files,
                )
                detached = CONTENT if packaging == "DETACHED" else None
                [report] = verify_xades(
                    signed.read_bytes(), pki.store, content=detached, online=False
                ).signatures
                ours = f"{report.indication.name}/{report.subindication or '-'}"
                stamps = [report.timestamp] if report.timestamp else []
                stamps += list(report.archive_timestamps)
                if stamps:
                    ours += " (sellos: " + ", ".join(s.indication.name for s in stamps) + ")"
                args = [str(signed), str(out / "raiz-pruebas.pem"), str(out / f"informe-{name}")]
                if packaging == "DETACHED":
                    args.append(str(document))
                line = _java(dssval, "Validate", *args).splitlines()
                theirs = line[0].split(" | ", 1)[-1] if line else "sin resultado"
                print(f"| {name} | {ours} | {theirs} |")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2] if len(sys.argv) > 2 else "spikes/spk03/dssval"))
