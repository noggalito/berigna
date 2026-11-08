# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing a PDF (CU-01, CU-03; BRG-UX-001 §3.2 and §3.3) or any other file (CU-05).

A PDF is previewed; any other file, which cannot always be shown, is presented by its name,
size, type and SHA-256, and as text when it is text (WYSIWYS), and signed in CAdES or, if it
is XML, in XAdES, in the packaging the user chooses.

The core runs in a worker thread (:func:`berigna.core.signing.sign_pdf_file`,
:func:`~berigna.core.signing.sign_cades_file`, :func:`~berigna.core.signing.sign_xades_file`):
it validates the certificate and probes the TSA before asking for the PIN through a callback,
which shows the PIN dialog (:mod:`berigna.ui.pin_dialog`) in the main loop and waits for the
user. The PIN is sent once per explicit confirmation (P-06); after a wrong PIN the user starts
again, with the remaining tries shown (P-07).

The form is made of the parts it shares with the batch page (:mod:`berigna.ui.signing_form`)
and, for a PDF, the visible signature (:mod:`berigna.ui.visible_signature`); this module keeps
the page, the signing flow and what both pages record or show when it ends.
"""

import datetime as dt
import hashlib
import logging
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402
from pyhanko.sign.timestamps import TimeStamper  # noqa: E402

from berigna.core.appearance import AppearanceKind, VisibleSignature  # noqa: E402
from berigna.core.documents import DocumentInfo, DocumentKind  # noqa: E402
from berigna.core.errors import (  # noqa: E402
    BerignaError,
    LevelNotAvailableError,
    PinBlockedError,
    PinIncorrectError,
    SignerCertificateError,
    SigningCancelledError,
    TokenError,
)
from berigna.core.formats.cades import CadesPackaging  # noqa: E402
from berigna.core.formats.pades import SignatureLevel  # noqa: E402
from berigna.core.history import Entry, History, Kind  # noqa: E402
from berigna.core.report.explanations import common_name, explain_error  # noqa: E402
from berigna.core.signing import (  # noqa: E402
    AskPin,
    Packaging,
    SignResult,
    sign_cades_file,
    sign_pdf_file,
    sign_xades_file,
    signed_output_path,
)
from berigna.core.token.base import TokenSigner  # noqa: E402
from berigna.core.token.pin import Pin  # noqa: E402
from berigna.core.trust import TrustStore  # noqa: E402
from berigna.core.validation import SignerCheck  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.i18n import _, catalogue  # noqa: E402
from berigna.ui.pin_dialog import PinDialog, ask_pin_in_main_loop  # noqa: E402
from berigna.ui.preview import PdfPreview  # noqa: E402
from berigna.ui.signing_form import (  # noqa: E402
    LevelChoice,
    PackagingChoice,
    SignatureData,
    digest_setting,
    file_view,
    output_settings,
)
from berigna.ui.visible_signature import VisibleSignatureChoice  # noqa: E402
from berigna.ui.widgets import (  # noqa: E402
    brand_markup,
)

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SigningServices:
    """What signing needs from the application; tests replace the card and the network."""

    open_token: Callable[[], TokenSigner]
    trust_store: Callable[[], TrustStore]
    timestamper: Callable[[], TimeStamper | None]  # None: no TSA configured (DP-02)
    settings: Gio.Settings | None
    online: bool = True
    appearance_dir: Path | None = None  # preloaded rubric and logo (None: none available)
    history: Callable[[], History | None] = lambda: None  # None: history switched off

    def record(self, entry: Entry) -> None:
        """Add ``entry`` to the history (RF-082), if kept; a failure never stops signing."""
        history = self.history()
        if history is None:
            return
        try:
            history.record(entry)
        except (OSError, sqlite3.Error):
            log.exception("history not updated")


REVOCATION_UNCHECKED = "revocation-unchecked"  # history detail of RF-006


def signature_entry(
    kind: Kind,
    name: str,
    sha256: str,
    check: SignerCheck,
    result: SignResult | None,
    code: str | None,
    level: SignatureLevel,
) -> Entry:
    """The history row of one signed (or failed) document."""
    certificate = check.chain[-1]
    return Entry(
        moment=dt.datetime.now(dt.UTC),
        kind=kind,
        file_name=name,
        file_sha256=sha256,
        result="ok" if result is not None else "error",
        signed_name=result.output.name if result else None,
        signed_sha256=result.sha256 if result else None,
        level=(result.level if result else level).value,
        signer=common_name(certificate),
        signer_serial=format(certificate.serial_number, "x"),
        # RF-006: a signature made without checking revocation is recorded as such.
        detail=code or (REVOCATION_UNCHECKED if result and not result.revocation_checked else None),
    )


def failure_page(
    window: "MainWindow",
    error: BerignaError | None,
    level: SignatureLevel,
    *,
    title: str,
    back: Callable[[], None],
    retry: Callable[[SignatureLevel], None],
) -> Adw.StatusPage | None:
    """What a failed signing shows, for one document or a batch; None when the flow goes on
    by itself (cancelled before the PIN, or a wrong PIN with tries left)."""
    if isinstance(error, SigningCancelledError):
        back()
        window.toast(_("Signature cancelled. The PIN was not sent."))
        return None
    if isinstance(error, PinIncorrectError) and error.remaining_tries != 0:
        # CU-01 6a: back to the PIN dialog, which shows the tries left (P-07). Sending the PIN
        # again still needs the user to type it and confirm (P-06).
        retry(level)
        return None
    if isinstance(error, PinIncorrectError):  # no tries left: the card is now blocked
        error = PinBlockedError("no tries left")
    message = explain_error(error.code if error else "ERR-000", catalogue()) or ""
    page = Adw.StatusPage(
        icon_name="dialog-error-symbolic", title=title, description=brand_markup(message)
    )
    buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
    back_button = Gtk.Button(label=_("_Back"), use_underline=True)
    back_button.add_css_class("pill")
    back_button.connect("clicked", lambda _b: back())
    buttons.append(back_button)
    if isinstance(error, (TokenError, SignerCertificateError)):
        diagnosis = Gtk.Button(label=_("_Diagnosis"), use_underline=True)
        diagnosis.add_css_class("pill")
        diagnosis.connect("clicked", lambda _b: window.show_diagnostics())
        buttons.append(diagnosis)
    if isinstance(error, LevelNotAvailableError) and level is not SignatureLevel.B_B:
        basic = Gtk.Button(label=_("Sign Without _Timestamp (B-B)"), use_underline=True)
        basic.add_css_class("pill")
        basic.add_css_class("suggested-action")
        basic.connect("clicked", lambda _b: retry(SignatureLevel.B_B))
        buttons.append(basic)
    page.set_child(buttons)
    return page


class SigningPage:
    """Preview, level and signature data of a PDF, or the file and its packaging (CU-05),
    and the signing flow."""

    def __init__(
        self,
        window: "MainWindow",
        document: DocumentInfo,
        services: SigningServices,
        *,
        existing_problems: bool = False,
    ) -> None:
        self._window = window
        self._services = services
        self.data = document.path.read_bytes()
        # What is signed is what is previewed (RF-018): the hash of these very bytes.
        self.document = DocumentInfo(
            document.path,
            document.kind,
            len(self.data),
            hashlib.sha256(self.data).hexdigest(),
            document.pages,
            document.signatures,
            document.locked,
        )
        self._remaining_tries: int | None = None
        self.result: SignResult | None = None
        self.pin_dialog: PinDialog | None = None
        self._check: SignerCheck | None = None  # set when the PIN is asked
        self.preview: PdfPreview | None = None  # PDF only
        self.formats: PackagingChoice | None = None  # any other file (CU-05)
        self.visible: VisibleSignatureChoice | None = None  # a PDF with pages (CU-02)

        self._sign = Gtk.Button(label=_("_Sign"), use_underline=True)
        self._sign.add_css_class("suggested-action")
        self._sign.connect("clicked", lambda _b: self.start())

        self._stack = Gtk.Stack()
        self._stack.add_named(self._form(existing_problems), "form")
        self._stack.add_named(self._busy(), "busy")
        self.page = window.page(document.path.name, "signing", self._stack, [self._sign])
        self._sign.set_sensitive(not document.locked)

    # -- Form ----------------------------------------------------------------------------------

    def _form(self, existing_problems: bool) -> Gtk.Widget:
        panel = Adw.PreferencesPage(width_request=340, hexpand=False)
        notices = []
        if self.document.locked:
            notices.append(explain_error("ERR-307", catalogue()) or "")
        if existing_problems:
            notices.append(
                _(
                    "Some of the signatures already in this document are not valid. "
                    "Your signature will be added anyway."
                )
            )
        if notices:
            group = Adw.PreferencesGroup()
            for notice in notices:
                row = Adw.ActionRow(title=brand_markup(notice), title_lines=0)
                row.add_prefix(Gtk.Image(icon_name="dialog-warning-symbolic"))
                group.add(row)
            panel.add(group)

        if self.document.kind is not DocumentKind.PDF:  # CU-05
            self.formats = PackagingChoice(self.document)
            panel.add(self.formats.group)
        self.levels = LevelChoice(self._services)
        self.level_buttons = self.levels.buttons
        panel.add(self.levels.group)
        self.signature_data = SignatureData(self._services.settings)
        self.reason = self.signature_data.reason
        self.location = self.signature_data.location

        layout = Gtk.Box()
        if self.formats is not None:  # reason and location are fields of PAdES only
            layout.append(file_view(self.document, self.data))
        else:
            self.preview = PdfPreview(self.data)
            if self.preview.page_count:  # CU-02
                self.visible = VisibleSignatureChoice(
                    self.preview,
                    self.signature_data,
                    self._services.settings,
                    self._services.appearance_dir,
                )
                self.appearance = self.visible.combo
                panel.add(self.visible.group)
            panel.add(self.signature_data.group)
            layout.append(self.preview)
        layout.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        layout.append(panel)
        return layout

    def reason_value(self) -> str | None:
        return self.signature_data.reason_value()

    def location_value(self) -> str | None:
        return self.signature_data.location_value()

    def appearance_kind(self) -> AppearanceKind | None:
        """The chosen appearance; None: not visible (or a document without pages)."""
        return self.visible.kind() if self.visible is not None else None

    def visible_signature(self) -> VisibleSignature | None:
        # without pages (Poppler could not draw them) there is no appearance list either
        return self.visible.signature() if self.visible is not None else None

    def _busy(self) -> Gtk.Widget:
        self._busy_page = Adw.StatusPage(paintable=Adw.SpinnerPaintable())
        self._busy_page.get_paintable().set_widget(self._busy_page)
        return self._busy_page

    def _set_busy(self, title: str) -> bool:
        self._busy_page.set_title(title)
        self._stack.set_visible_child_name("busy")
        self._sign.set_sensitive(False)
        return GLib.SOURCE_REMOVE

    def _back_to_form(self) -> None:
        self._stack.set_visible_child_name("form")
        self._sign.set_sensitive(not self.document.locked)

    def _show(self, name: str, child: Gtk.Widget) -> None:
        old = self._stack.get_child_by_name(name)
        if old is not None:
            self._stack.remove(old)
        self._stack.add_named(child, name)
        self._stack.set_visible_child_name(name)

    # -- Flow ----------------------------------------------------------------------------------

    def packaging(self) -> Packaging:
        """The chosen packaging of CAdES or XAdES; None for a PDF (PAdES)."""
        return self.formats.packaging if self.formats is not None else None

    def start(self, level: SignatureLevel | None = None) -> None:
        """Sign at ``level`` (the chosen one by default) in a worker thread."""
        level = level or self.levels.level
        packaging = self.packaging()
        suffix, directory = output_settings(self._services.settings)
        output = signed_output_path(self.document.path, packaging, suffix, directory)
        sign = self._signer(packaging)
        self._set_busy(_("Checking your certificate…"))
        services = self._services

        def work() -> None:
            try:
                with services.open_token() as token:
                    result = sign(
                        output,
                        token,
                        services.trust_store(),
                        lambda check: self._ask_pin(check, level, packaging),
                        level,
                        services.timestamper(),
                    )
            except BerignaError as exc:
                GLib.idle_add(self._failed, exc, level)
            except Exception:  # never leave the page waiting: report it as unexpected (ERR-000)
                log.exception("signing failed")
                GLib.idle_add(self._failed, None, level)
            else:
                if result.level_note:
                    log.info("level %s reached: %s", result.level.value, result.level_note)
                GLib.idle_add(self._done, result, level)

        threading.Thread(target=work, name="berigna-sign", daemon=True).start()

    def _signer(
        self, packaging: Packaging
    ) -> Callable[
        [Path, TokenSigner, TrustStore, AskPin, SignatureLevel, TimeStamper | None],
        SignResult,
    ]:
        """The core call for ``packaging``, with what the form says, read in the main loop."""
        path, sha256, online = self.document.path, self.document.sha256, self._services.online
        if packaging is None:
            self.signature_data.remember()
            options = self.signature_data.options()
            visible = self.visible_signature()
            return lambda output, token, store, ask_pin, level, stamper: sign_pdf_file(
                path,
                output,
                expected_sha256=sha256,
                token=token,
                store=store,
                ask_pin=ask_pin,
                options=options,
                level=level,
                timestamper=stamper,
                online=online,
                visible=visible,
            )
        digest = digest_setting(self._services.settings)
        if isinstance(packaging, CadesPackaging):
            return lambda output, token, store, ask_pin, level, stamper: sign_cades_file(
                path,
                output,
                expected_sha256=sha256,
                token=token,
                store=store,
                ask_pin=ask_pin,
                packaging=packaging,
                level=level,
                digest=digest,
                timestamper=stamper,
                online=online,
            )
        return lambda output, token, store, ask_pin, level, stamper: sign_xades_file(
            path,
            output,
            expected_sha256=sha256,
            token=token,
            store=store,
            ask_pin=ask_pin,
            packaging=packaging,
            level=level,
            digest=digest,
            timestamper=stamper,
            online=online,
        )

    def _ask_pin(
        self, check: SignerCheck, level: SignatureLevel, packaging: Packaging = None
    ) -> Pin | None:
        self._check = check

        def dialog(reply: Callable[[Pin | None], None]) -> PinDialog:
            self.pin_dialog = PinDialog(
                self.document, check, level, self._remaining_tries, reply, packaging
            )
            return self.pin_dialog

        return ask_pin_in_main_loop(
            self._window, dialog, lambda: self._set_busy(_("Signing with your DNIe…"))
        )

    def _record(self, result: SignResult | None, code: str | None, level: SignatureLevel) -> None:
        """RF-082: once the PIN was sent, the outcome goes to the history."""
        check = self._check
        if check is None:
            return
        history = self._services.history()
        name = history.name(self.document.path) if history else self.document.path.name
        self._services.record(
            signature_entry(Kind.SIGN, name, self.document.sha256, check, result, code, level)
        )

    def _done(self, result: SignResult, requested: SignatureLevel) -> bool:
        self._record(result, None, requested)
        self.result = result
        self._remaining_tries = None
        page = Adw.StatusPage(
            icon_name="object-select-symbolic",
            title=_("Document signed"),
            description=brand_markup(presentation.signed_summary(result, requested)),
        )
        self._sign.set_visible(False)
        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER)
        for label, callback in (
            (_("_Open"), self._open_result),
            (_("Show in _Folder"), self._show_in_folder),
            (_("_Verify"), self._verify_result),
        ):
            button = Gtk.Button(label=label, use_underline=True)
            button.add_css_class("pill")
            button.connect("clicked", lambda _b, c=callback: c())
            buttons.append(button)
        page.set_child(buttons)
        self._show("done", page)
        return GLib.SOURCE_REMOVE

    def _failed(self, error: BerignaError | None, level: SignatureLevel) -> bool:
        if isinstance(error, PinIncorrectError) and error.remaining_tries != 0:
            self._remaining_tries = error.remaining_tries
        elif not isinstance(error, (SigningCancelledError, PinIncorrectError)):
            self._record(None, error.code if error else "ERR-000", level)
        self._check = None
        page = failure_page(
            self._window,
            error,
            level,
            title=_("The document was not signed"),
            back=self._back_to_form,
            retry=self.start,
        )
        if page is not None:
            self._show("error", page)
        return GLib.SOURCE_REMOVE

    # -- After signing -------------------------------------------------------------------------

    def _open_result(self) -> None:
        if self.result is not None:
            launcher = Gtk.FileLauncher(file=Gio.File.new_for_path(str(self.result.output)))
            launcher.launch(self._window.window, None, None)

    def _show_in_folder(self) -> None:
        if self.result is not None:
            launcher = Gtk.FileLauncher(file=Gio.File.new_for_path(str(self.result.output)))
            launcher.open_containing_folder(self._window.window, None, None)

    def _verify_result(self) -> None:
        if self.result is not None:
            self._window.open_file(Gio.File.new_for_path(str(self.result.output)))
