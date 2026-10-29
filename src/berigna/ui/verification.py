# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verification of a signed PDF (CU-06, BRG-UX-001 §3.4): result, details and reports.

The verification runs in a worker thread: it may query OCSP and CRL services for seconds
(R-17). A result that arrives after the user moved to another document is dropped.
"""

import datetime as dt
import hashlib
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from berigna.core.documents import DocumentInfo  # noqa: E402
from berigna.core.errors import BerignaError  # noqa: E402
from berigna.core.files import write_atomically  # noqa: E402
from berigna.core.history import Entry, Kind  # noqa: E402
from berigna.core.i18n import Language, translations  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.report.json_report import dumps, report_data  # noqa: E402
from berigna.core.report.pdf_report import pdf_report  # noqa: E402
from berigna.core.trust import TrustStore  # noqa: E402
from berigna.core.validation import Indication, PdfVerification  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.i18n import N_, _, catalogue, current_language  # noqa: E402
from berigna.ui.widgets import brand_markup, named  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow

log = logging.getLogger(__name__)

# Verifies the bytes of a PDF; returns the result and the trust store it used.
Verify = Callable[[bytes], tuple[PdfVerification, TrustStore]]

REPORTS = {
    # kind: (suggested file name, language of a PDF report or None for JSON)
    "pdf-es": (N_("{stem} - verification report.pdf"), Language.ES_PE),
    "pdf-quz": (N_("{stem} - verification report (Quechua).pdf"), Language.QUZ_PE),
    "json": (N_("{stem} - verification report.json"), None),
}
SIGNED_VERSION = N_("{stem} - signed version {number}.pdf")


class VerificationPage:
    def __init__(self, window: "MainWindow", document: DocumentInfo, verify: Verify) -> None:
        self._window = window
        self.document = document
        self._verify = verify
        self.verification: PdfVerification | None = None
        self._store: TrustStore | None = None
        self._data = b""
        self._sha256 = ""
        self._existing_problems = False

        menu = Gio.Menu()
        menu.append(_("PDF Report in Spanish"), "verification.export::pdf-es")
        menu.append(_("PDF Report in Quechua"), "verification.export::pdf-quz")
        menu.append(_("JSON Report"), "verification.export::json")
        self._export = Gtk.MenuButton(
            label=_("Export"), menu_model=menu, sensitive=False, tooltip_text=_("Export Report")
        )
        self._sign = Gtk.Button(
            label=_("_Sign"),
            use_underline=True,
            sensitive=False,
            tooltip_text=_("Add your signature to this document"),
        )
        self._sign.add_css_class("suggested-action")
        self._sign.connect("clicked", lambda _b: self._add_signature())
        self._retry = named(
            Gtk.Button(
                icon_name="view-refresh-symbolic",
                tooltip_text=_("Verify Again"),
                action_name="verification.verify-again",
                visible=False,
            )
        )
        self._stack = Gtk.Stack()
        spinner = Adw.StatusPage(
            title=_("Verifying signatures…"),
            description=_("Checking the certificates may take a few seconds."),
            paintable=Adw.SpinnerPaintable(),
        )
        spinner.get_paintable().set_widget(spinner)
        self._stack.add_named(spinner, "loading")
        self.page = window.page(
            document.path.name, "verification", self._stack, [self._sign, self._export, self._retry]
        )

        actions = Gio.SimpleActionGroup()
        for name, parameter, callback in (
            ("export", GLib.VariantType.new("s"), self._on_export),
            ("save-revision", GLib.VariantType.new("u"), self._on_save_revision),
            ("verify-again", None, lambda *_args: self.start()),
        ):
            action = Gio.SimpleAction.new(name, parameter)
            action.connect("activate", callback)
            actions.add_action(action)
        self.page.insert_action_group("verification", actions)
        self.start()

    @property
    def current(self) -> bool:
        return self._window.verification is self

    def start(self) -> None:
        """Verify in a worker thread; the page shows a spinner meanwhile."""
        self._stack.set_visible_child_name("loading")
        self._export.set_sensitive(False)
        self._sign.set_sensitive(False)
        self._retry.set_visible(False)

        def work() -> None:
            try:
                data = self.document.path.read_bytes()
                verification, store = self._verify(data)
                GLib.idle_add(self._show_result, data, verification, store)
            except BerignaError as exc:
                GLib.idle_add(self._show_error, explain_error(exc.code, catalogue()) or "")
            except OSError:
                GLib.idle_add(
                    self._show_error,
                    _("{name} could not be opened.").format(name=self.document.path.name),
                )
            except Exception:  # never leave the spinner turning: unexpected error (ERR-000)
                log.exception("verification failed")
                GLib.idle_add(self._show_error, explain_error("ERR-000", catalogue()) or "")

        threading.Thread(target=work, name="berigna-verify", daemon=True).start()

    def _show_error(self, message: str) -> bool:
        if self.current:
            error = Adw.StatusPage(
                icon_name="dialog-error-symbolic",
                title=_("The document could not be verified"),
                description=brand_markup(message),
            )
            self._replace("error", error)
        return GLib.SOURCE_REMOVE

    def _record(self, verification: PdfVerification) -> None:
        """RF-082: the worst indication of the document and how many signatures passed."""
        services = self._window.services
        history = services.history()
        if history is None:
            return
        indications = [s.indication for s in verification.signatures]
        indications += [t.indication for t in verification.document_timestamps]
        worst = next(
            (i for i in (Indication.TOTAL_FAILED, Indication.INDETERMINATE) if i in indications),
            Indication.TOTAL_PASSED,
        )
        passed = sum(s.indication is Indication.TOTAL_PASSED for s in verification.signatures)
        services.record(
            Entry(
                moment=dt.datetime.now(dt.UTC),
                kind=Kind.VERIFY,
                file_name=history.name(self.document.path),
                file_sha256=self._sha256,
                result=worst.value,
                detail=f"{passed}/{len(verification.signatures)}",
            )
        )

    def _replace(self, name: str, child: Gtk.Widget) -> None:
        old = self._stack.get_child_by_name(name)
        if old is not None:
            self._stack.remove(old)
        self._stack.add_named(child, name)
        self._stack.set_visible_child_name(name)

    def _show_result(self, data: bytes, verification: PdfVerification, store: TrustStore) -> bool:
        if not self.current:
            return GLib.SOURCE_REMOVE
        self._data = data
        self._sha256 = hashlib.sha256(data).hexdigest()
        self.verification, self._store = verification, store
        view = presentation.verification_view(verification, store)
        self._record(verification)

        result = Adw.PreferencesPage()
        summary = Adw.PreferencesGroup()
        self.summary_row = Adw.ActionRow(title=view.summary, title_lines=0, use_markup=False)
        self.summary_row.add_prefix(_icon(view.icon, view.style))
        if current_language() is Language.QUZ_PE:
            spanish = Gtk.Button(label=_("Show in Spanish"), valign=Gtk.Align.CENTER)
            spanish.add_css_class("flat")
            spanish.connect("clicked", lambda _b: self.show_spanish())
            self.summary_row.add_suffix(spanish)
        summary.add(self.summary_row)
        result.add(summary)
        for number, signature in enumerate(view.signatures, start=1):
            result.add(self._result_group(signature, number))
        if view.timestamps:
            stamps = Adw.PreferencesGroup(title=_("Document time-stamps"))
            for stamp in view.timestamps:
                expander = _details(stamp, title=stamp.title, subtitle=stamp.explanation)
                expander.add_prefix(_icon(stamp.icon, stamp.style))
                stamps.add(expander)
            result.add(stamps)

        self._replace("result", result)
        self._export.set_sensitive(True)
        self._sign.set_sensitive(not self.document.locked)
        self._retry.set_visible(view.retry)
        self._existing_problems = view.style != "success"
        return GLib.SOURCE_REMOVE

    def show_spanish(self) -> Adw.AlertDialog:
        """The result in Spanish, without changing the language (BRG-UX-001 §4.2)."""
        if self.verification is None or self._store is None:
            raise RuntimeError("no verification result yet")
        spanish = translations(Language.ES_PE)
        view = presentation.verification_view(self.verification, self._store, spanish)
        results = (*view.signatures, *view.timestamps)
        body = "\n\n".join([view.summary, *(f"{r.title}: {r.explanation}" for r in results)])
        dialog = Adw.AlertDialog(heading=self.document.path.name, body=body)
        dialog.add_response("close", spanish.gettext("_Close"))
        dialog.present(self._window.window)
        return dialog

    def _result_group(self, view: presentation.ResultView, number: int) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(title=view.title, description=brand_markup(view.explanation))
        group.set_header_suffix(_icon(view.icon, view.style))
        expander = _details(view, title=_("Technical Details"))
        save = named(
            Gtk.Button(
                icon_name="document-save-symbolic",
                tooltip_text=_("Save the Signed Version"),
                valign=Gtk.Align.CENTER,
                action_name="verification.save-revision",
                action_target=GLib.Variant.new_uint32(number),
            )
        )
        save.add_css_class("flat")
        revision = Adw.ActionRow(
            title=_("Save the Signed Version"),
            subtitle=_("The document as this signature left it"),
            use_markup=False,
        )
        revision.add_suffix(save)
        expander.add_row(revision)
        group.add(expander)
        return group

    def _add_signature(self) -> None:
        """CU-03: sign on top; warn first if some existing signature is not valid."""
        self._window.sign(self.document, existing_problems=self._existing_problems)

    # -- Reports and signed versions -------------------------------------------------------

    def report(self, kind: str) -> bytes:
        """The report of the shown result: ``pdf-es``, ``pdf-quz`` or ``json``."""
        if self.verification is None or self._store is None:
            raise RuntimeError("no verification result yet")
        _name, language = REPORTS[kind]
        name, digest = self.document.path.name, self._sha256
        if language is None:
            data = report_data(
                self.verification, file_name=name, file_sha256=digest, store=self._store
            )
            return dumps(data).encode()
        return pdf_report(
            self.verification,
            file_name=name,
            file_sha256=digest,
            store=self._store,
            language=language,
        )

    def signed_revision(self, number: int) -> bytes:
        """The document as signature ``number`` (from 1) left it (CU-06)."""
        if self.verification is None:
            raise RuntimeError("no verification result yet")
        length = self.verification.signatures[number - 1].signed_revision_length
        return self._data[:length]

    def save(self, path: Path, data: bytes) -> None:
        """Write a file the user chose in the save dialog, which confirmed any overwrite."""
        try:
            write_atomically(path, data, replace=True)
        except OSError:
            self._window.toast(_("{name} could not be saved.").format(name=path.name))
        else:
            self._window.toast(_("Saved {name}").format(name=path.name))

    def _on_export(self, _action: Gio.SimpleAction, parameter: GLib.Variant) -> None:
        kind = parameter.get_string()
        pattern, _language = REPORTS[kind]
        name = _(pattern).format(stem=self.document.path.stem)
        self._ask_path(name, lambda _path: self.report(kind))

    def _on_save_revision(self, _action: Gio.SimpleAction, parameter: GLib.Variant) -> None:
        number = parameter.get_uint32()
        name = _(SIGNED_VERSION).format(stem=self.document.path.stem, number=number)
        self._ask_path(name, lambda _path: self.signed_revision(number))

    def _ask_path(self, name: str, contents: Callable[[Path], bytes]) -> None:
        dialog = Gtk.FileDialog(
            initial_name=name, initial_folder=Gio.File.new_for_path(str(self.document.path.parent))
        )

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                path = Path(dialog.save_finish(result).get_path())
            except GLib.Error:  # dismissed by the user
                return
            self.save(path, contents(path))

        dialog.save(self._window.window, None, chosen)


def _icon(name: str, style: str) -> Gtk.Image:
    image = Gtk.Image(icon_name=name, accessible_role=Gtk.AccessibleRole.PRESENTATION)
    image.add_css_class(style)
    return image


def _details(view: presentation.ResultView, *, title: str, subtitle: str = "") -> Adw.ExpanderRow:
    # use_markup=False: names and fields come from the document, never as markup.
    expander = Adw.ExpanderRow(title=title, subtitle=subtitle, use_markup=False)
    expander.set_subtitle_lines(0)
    for detail in view.details:
        row = Adw.ActionRow(
            title=detail.label, subtitle=detail.value, subtitle_selectable=True, use_markup=False
        )
        row.add_css_class("property")
        expander.add_row(row)
    return expander
