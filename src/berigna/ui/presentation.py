# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Texts and icons the window shows, kept apart from GTK so they can be tested headless."""

from dataclasses import dataclass

from berigna.core.documents import DocumentInfo, DocumentKind
from berigna.core.token.monitor import DeviceState, DeviceStatus
from berigna.ui.i18n import N_, _, ngettext

# Shown in Quechua and in Spanish while no speaker has reviewed the translation (DP-14,
# BRG-UX-001 §4.2).
UNREVIEWED_TRANSLATION = N_(
    "Translation not reviewed by speakers. If in doubt, the Spanish text prevails."
)


@dataclass(frozen=True)
class StatusView:
    icon: str
    message: str
    ready: bool = False


_DEVICE: dict[DeviceState, tuple[str, str]] = {
    DeviceState.PCSC_UNAVAILABLE: (
        "dialog-warning-symbolic",
        N_("The smart card service (pcscd) is not running"),
    ),
    DeviceState.NO_READER: ("media-removable-symbolic", N_("Connect a card reader")),
    DeviceState.NO_CARD: ("contact-new-symbolic", N_("Insert your DNIe in the reader")),
    DeviceState.UNSUPPORTED_CARD: ("dialog-warning-symbolic", N_("This card is not supported")),
    DeviceState.DNIE_READY: ("emblem-ok-symbolic", N_("DNIe ready")),
}


def device_status(status: DeviceStatus | None) -> StatusView:
    """Status bar contents; ``None`` before the first sample of the monitor."""
    if status is None:
        return StatusView("content-loading-symbolic", _("Looking for card readers…"))
    icon, message = _DEVICE[status.state]
    return StatusView(icon, _(message), ready=status.state is DeviceState.DNIE_READY)


def document_summary(info: DocumentInfo) -> str:
    """One line about an opened document: kind, pages and signatures."""
    if info.kind is DocumentKind.OTHER:
        return _("berigna cannot sign or verify this kind of file yet.")
    pages = info.pages or 0
    text = ngettext("PDF document, {n} page", "PDF document, {n} pages", pages).format(n=pages)
    if not info.signed:
        return _("{document}, not signed").format(document=text)
    signatures = ngettext("{n} signature", "{n} signatures", info.signatures).format(
        n=info.signatures
    )
    return _("{document}, {signatures}").format(document=text, signatures=signatures)
