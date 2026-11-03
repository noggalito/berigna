#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Weekly check of the external services berigna depends on (BRG-MAN-001 §5, R-DES-01, R-17).

- The trusted list of INDECOPI: downloaded and verified as berigna does (``fetch_tsl``), and
  how long until its NextUpdate.
- The CRLs of the CAs (ARL) that the bundled certificates point to: each mirror answers, the
  list is signed by its CA and is current.
- The OCSP responder of RENIEC (the one in the DNIe certificates, SPK-01): it answers a
  well-formed OCSP response.
- Published vulnerabilities of the components that do not come from Debian (today only
  pyHanko, R-DES-02), in OSV, from the SBOM.

Exits with 1 when something fails, so that the weekly workflow opens an issue; the table
goes to the job summary on GitHub Actions. Never uses a DNIe or a PIN.

    .venv/bin/python scripts/vigilar-servicios.py [--sbom build/sbom.cdx.json]
"""

import argparse
import datetime as dt
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import requests  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509 import ocsp  # noqa: E402

from berigna.core.trust import TrustStore  # noqa: E402
from berigna.core.trust.tsl import describe, fetch_tsl  # noqa: E402

TIMEOUT = 60.0  # crl2.reniec.gob.pe takes ~15 s on the first request (core.net.fetchers)
RENIEC_OCSP = "http://ocsp.reniec.gob.pe"  # authorityInfoAccess of the DNIe v2 certificates
OSV = "https://api.osv.dev/v1/query"
TSL_MARGIN = dt.timedelta(days=7)  # warn when the list is about to expire

Check = tuple[str, bool, str]  # what, passed, detail


def _tsl() -> list[Check]:
    trusted, _data = fetch_tsl(timeout=TIMEOUT)
    left = trusted.next_update - dt.datetime.now(dt.UTC)
    return [
        ("TSL de INDECOPI: descarga y firma", True, describe(trusted)),
        (
            "TSL de INDECOPI: vigencia",
            left > TSL_MARGIN,
            f"{left.days} días hasta NextUpdate ({trusted.next_update:%Y-%m-%d})",
        ),
    ]


def _crl_urls(certificate: x509.Certificate) -> list[str]:
    try:
        points = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []
    return [
        name.value
        for point in points.value
        for name in point.full_name or []
        if isinstance(name, x509.UniformResourceIdentifier)
    ]


def _crls(store: TrustStore) -> list[Check]:
    certificates = [*store.roots, *store.intermediates]
    issuers = {c.subject.public_bytes(): c for c in certificates}
    urls = dict.fromkeys(url for c in certificates for url in _crl_urls(c))
    checks = []
    now = dt.datetime.now(dt.UTC)
    for url in urls:
        try:
            answer = requests.get(url, timeout=TIMEOUT)
            answer.raise_for_status()
            crl = x509.load_der_x509_crl(answer.content)
            issuer = issuers.get(crl.issuer.public_bytes())
            signed = issuer is not None and crl.is_signature_valid(issuer.public_key())  # type: ignore[arg-type]
            following = crl.next_update_utc
            current = following is not None and following > now
            detail = (
                f"próxima actualización {following:%Y-%m-%d}" if following else "sin nextUpdate"
            )
            if not signed:
                detail = "la firma de la lista no es de su CA; " + detail
            checks.append((f"CRL {url}", signed and current, detail))
        except Exception as exc:  # one mirror must not hide the others
            checks.append((f"CRL {url}", False, f"{type(exc).__name__}: {exc}"))
    return checks


def _ocsp(store: TrustStore) -> list[Check]:
    """A request for a RENIEC CA certificate: any well-formed answer shows the service is up
    (the responder may say "unauthorized" for a certificate it does not serve)."""
    by_subject = {c.subject.public_bytes(): c for c in [*store.roots, *store.intermediates]}
    subject = next(
        c
        for c in store.intermediates
        if "Class 2 II" in c.subject.rfc4514_string() and c.issuer.public_bytes() in by_subject
    )
    issuer = by_subject[subject.issuer.public_bytes()]
    request = (
        ocsp.OCSPRequestBuilder().add_certificate(subject, issuer, hashes.SHA1()).build()  # noqa: S303 - CertID of RFC 6960
    )
    try:
        answer = requests.post(
            RENIEC_OCSP,
            data=request.public_bytes(serialization.Encoding.DER),
            headers={"Content-Type": "application/ocsp-request"},
            timeout=TIMEOUT,
        )
        answer.raise_for_status()
        status = ocsp.load_der_ocsp_response(answer.content).response_status
    except (requests.RequestException, ValueError) as exc:
        return [(f"OCSP {RENIEC_OCSP}", False, f"{type(exc).__name__}: {exc}")]
    return [(f"OCSP {RENIEC_OCSP}", True, f"respuesta {status.name}")]


def _osv(sbom: Path | None) -> list[Check]:
    """OSV for the components of the SBOM that come from PyPI, not from Debian."""
    if sbom is None:
        return []
    components = json.loads(sbom.read_text(encoding="utf-8"))["components"]
    checks = []
    for component in components:
        if not str(component.get("purl", "")).startswith("pkg:pypi/"):
            continue
        query = {
            "package": {"name": component["name"], "ecosystem": "PyPI"},
            "version": component["version"],
        }
        what = f"OSV {component['name']} {component['version']}"
        try:
            answer = requests.post(OSV, json=query, timeout=TIMEOUT)
            answer.raise_for_status()
            found = [v["id"] for v in answer.json().get("vulns", [])]
        except (requests.RequestException, ValueError) as exc:
            checks.append((what, False, f"{type(exc).__name__}: {exc}"))
            continue
        checks.append((what, not found, ", ".join(found) or "sin vulnerabilidades publicadas"))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sbom", type=Path, help="SBOM de scripts/sbom.py, para OSV")
    args = parser.parse_args()
    store = TrustStore.load_bundled()
    groups: list[tuple[str, Callable[[], list[Check]]]] = [
        ("TSL de INDECOPI", _tsl),
        ("CRL de las CA", lambda: _crls(store)),
        ("OCSP de RENIEC", lambda: _ocsp(store)),
        ("Vulnerabilidades (OSV)", lambda: _osv(args.sbom)),
    ]
    checks: list[Check] = []
    for name, group in groups:
        try:
            checks += group()
        except Exception as exc:  # one service must not hide the others
            checks.append((name, False, f"{type(exc).__name__}: {exc}"))
    lines = ["| Comprobación | Resultado | Detalle |", "|---|---|---|"]
    lines += [f"| {what} | {'bien' if ok else 'FALLA'} | {detail} |" for what, ok, detail in checks]
    table = "\n".join(lines)
    print(table)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as out:
            out.write(f"## Servicios externos\n\n{table}\n")
    return 0 if all(ok for _what, ok, _detail in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
