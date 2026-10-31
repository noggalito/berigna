# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Settings of the ETSI EN 319 102-1 processes shared by the PDF and CAdES verifiers.

The indication of a signature and its subindication (§5.2), the report of a time-stamp
(§5.4) and the chain diagnosis that names the error pyHanko folds into
``CERTIFICATE_CHAIN_GENERAL_FAILURE`` (§5.2.6) live here, next to the validation
specification: the trust store, the algorithm policies (ACR-18) and the rules of revocation
data (RF-053, RF-063).
"""

import asyncio
import datetime as dt
import enum
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asn1crypto import cms
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from pyhanko.sign.ades.report import AdESFailure, AdESIndeterminate, AdESPassed
from pyhanko.sign.validation import ades
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.policy_decl import (
    LocalKnowledge,
    RevinfoOnlineFetchingRule,
    RevocationInfoGatheringSpec,
    SignatureValidationSpec,
    bootstrap_validation_data_handlers,
)
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator import CertificateValidator
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.errors import (
    ExpiredError,
    InsufficientRevinfoError,
    NotYetValidError,
    ValidationError,
)
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_certvalidator.revinfo.archival import CRLContainer, OCSPContainer

from berigna.core.certs import to_asn1, to_cryptography
from berigna.core.net.fetchers import RevocationFetcherBackend
from berigna.core.trust import TrustStore
from berigna.core.validation.algorithms import algorithm_policy, signature_algorithm_policy

VERIFICATION_POLICY = RevocationCheckingPolicy(
    ee_certificate_rule=RevocationCheckingRule.CRL_OR_OCSP_REQUIRED,
    intermediate_ca_cert_rule=RevocationCheckingRule.CRL_REQUIRED,
)


class Indication(enum.Enum):
    """Main indication of ETSI EN 319 102-1 §5.1.3."""

    TOTAL_PASSED = "TOTAL-PASSED"
    TOTAL_FAILED = "TOTAL-FAILED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class TimestampReport:
    """A signature time-stamp or a document time-stamp (RF-053)."""

    indication: Indication
    subindication: str | None
    time: dt.datetime | None  # the time certified by the TSA; None if unreadable
    tsa: x509.Certificate | None
    field_name: str | None = None  # set for document time-stamps


GENERIC_CHAIN_FAILURE = "CERTIFICATE_CHAIN_GENERAL_FAILURE"
# What pyHanko and asn1crypto raise on a signature they cannot process (AM-05). The PDF
# verifier adds the PDF-specific exceptions.
MALFORMED = (SignatureValidationError, ValueError, KeyError, TypeError)


@dataclass(frozen=True)
class Context:
    """What every signature of one file is validated with."""

    store: TrustStore
    extra_ocsps: list[Any]  # DER supplied by the caller, beyond the file itself
    extra_crls: list[Any]
    timing: ValidationTimingInfo
    tolerance: dt.timedelta
    online: bool
    timeout: float


def _as_asn1(certificates: Sequence[Any]) -> list[asn1_x509.Certificate]:
    """The certificates as asn1crypto values: the ones already asn1 (from a CMS or a DSS)
    stay as they are, the cryptography ones convert."""
    return [
        certificate if isinstance(certificate, asn1_x509.Certificate) else to_asn1(certificate)
        for certificate in certificates
    ]


def validation_spec(
    context: Context,
    known_certs: Sequence[Any],
    ocsps: Sequence[Any],
    crls: Sequence[Any],
) -> SignatureValidationSpec:
    """The ETSI validation spec: the trust roots of the store, the certificates of the file
    (and of the caller, PDF only) as known rather than trusted, the revocation data of the
    file plus whatever the store gathered; online only if allowed (RF-063)."""
    return SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(
                trust_roots=[to_asn1(c) for c in context.store.roots]
            ),
            revinfo_policy=CertRevTrustPolicy(VERIFICATION_POLICY),
            time_tolerance=context.tolerance,
            algorithm_usage_policy=algorithm_policy(),
        ),
        revinfo_gathering_policy=RevocationInfoGatheringSpec(
            online_fetching_rule=(
                RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH
                if context.online
                else RevinfoOnlineFetchingRule.LOCAL_ONLY
            ),
            fetcher_backend=RevocationFetcherBackend(context.timeout),
        ),
        local_knowledge=LocalKnowledge(
            known_certs=_as_asn1(known_certs),
            known_ocsps=[c for o in ocsps for c in OCSPContainer.load_multi(o)],
            known_crls=[CRLContainer(c) for c in crls],
        ),
        key_usage_settings=KeyUsageConstraints(key_usage={"non_repudiation"}),
        signature_algorithm_policy=signature_algorithm_policy(),
    )


def indication(subindic: Any) -> tuple[Indication, str | None]:
    """The ETSI main indication and subindication name of a pyHanko AdES result."""
    if isinstance(subindic, AdESPassed):
        return Indication.TOTAL_PASSED, None
    if isinstance(subindic, AdESFailure):
        return Indication.TOTAL_FAILED, subindic.name
    if isinstance(subindic, AdESIndeterminate):
        return Indication.INDETERMINATE, subindic.name
    raise TypeError(f"unexpected AdES subindication {subindic!r}")  # pragma: no cover


def timestamp_report(
    result: "ades.AdESBasicValidationResult[Any]", field_name: str | None = None
) -> TimestampReport:
    """The report of one validated time-stamp (its indication and the time certified)."""
    indicate, subindication = indication(result.ades_subindic)
    status = result.api_status
    return TimestampReport(
        indication=indicate,
        subindication=subindication,
        time=getattr(status, "timestamp", None),
        tsa=to_cryptography(status.signing_cert) if status is not None else None,
        field_name=field_name,
    )


def validate_timestamp(
    tst: cms.SignedData,
    imprint: bytes,
    spec: SignatureValidationSpec,
    timing: ValidationTimingInfo,
) -> "ades.AdESBasicValidationResult[Any]":
    """§5.4: one time-stamp token against the imprint it must cover."""
    return asyncio.run(
        ades.ades_timestamp_validation(tst, spec, expected_tst_imprint=imprint, timing_info=timing)
    )


def diagnose_chain(
    signed_data: cms.SignedData,
    signer_cert: asn1_x509.Certificate,
    spec: SignatureValidationSpec,
    timing: ValidationTimingInfo,
) -> str:
    """Name the ETSI subindication pyHanko folds into CERTIFICATE_CHAIN_GENERAL_FAILURE.

    pyHanko 0.25.1 reports missing revocation data and an expired CA certificate with that
    generic value; ETSI EN 319 102-1 (§5.2.6) distinguishes them. The chain is validated again
    on its own to see which error comes out. If it passes this time, the first failure was
    transient (a service that did not answer): TRY_LATER as well.
    """
    handlers = bootstrap_validation_data_handlers(spec, timing_info=timing)
    validation_context = spec.cert_validation_policy.build_validation_context(
        timing_info=timing, handlers=handlers
    )
    embedded = [c.chosen for c in signed_data["certificates"] if c.name == "certificate"]
    validator = CertificateValidator(
        signer_cert, intermediate_certs=embedded, validation_context=validation_context
    )
    try:
        asyncio.run(validator.async_validate_usage({"non_repudiation"}))  # type: ignore[no-untyped-call]
    except InsufficientRevinfoError:
        return "TRY_LATER"
    except NotYetValidError:
        return "NOT_YET_VALID"
    except ExpiredError:
        return "OUT_OF_BOUNDS_NO_POE"
    except ValidationError:
        return GENERIC_CHAIN_FAILURE
    return "TRY_LATER"
