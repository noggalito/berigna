# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""CAdES and XAdES signatures at B-B made by berigna through the DNIe simulator."""

from cryptography import x509

from berigna.core.formats.cades import CadesPackaging, sign_cades
from berigna.core.formats.xades import XadesPackaging, sign_xades
from berigna.core.token.dnie_v2 import DnieV2Token
from berigna.core.token.pin import Pin
from support.cards import make_card
from support.pki import Pki


def cades(
    pki: Pki, content: bytes, packaging: CadesPackaging = CadesPackaging.DETACHED
) -> tuple[bytes, x509.Certificate]:
    card, leaf = make_card(pki, "FIRMANTE CADES")
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_cades(content, token, (pki.root, pki.ca, leaf), packaging=packaging)
    return result.data, leaf


def xades(
    pki: Pki,
    content: bytes,
    packaging: XadesPackaging = XadesPackaging.ENVELOPED,
    reference_uri: str = "acta.xml",
) -> tuple[bytes, x509.Certificate]:
    card, leaf = make_card(pki, "FIRMANTE XADES")
    with DnieV2Token(card) as token:
        token.verify_pin(Pin("123456"))
        result = sign_xades(
            content,
            token,
            (pki.root, pki.ca, leaf),
            packaging=packaging,
            reference_uri=reference_uri if packaging is XadesPackaging.DETACHED else None,
        )
    return result.data, leaf
