# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Verification of a signed document (CU-06, BRG-UX-001 §3.4): result, details and reports.

A PDF (PAdES), a CAdES signature (``.p7s``, ``.p7m``) or an XML document with XAdES
signatures (``.xml``, ``.xsig``). A detached signature needs the file it signs: the one next
to it with the same name without the extension, or else the one the user chooses (RF-051).
The content of a ``.p7m`` can be saved (RF-051).

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

from berigna.core.documents import DocumentInfo, DocumentKind  # noqa: E402
from berigna.core.errors import BerignaError  # noqa: E402
from berigna.core.files import write_atomically  # noqa: E402
from berigna.core.history import Entry, Kind  # noqa: E402
from berigna.core.i18n import Language, translations  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.report.json_report import dumps, report_data  # noqa: E402
from berigna.core.report.pdf_report import pdf_report  # noqa: E402
from berigna.core.trust import TrustStore  # noqa: E402
from berigna.core.validation import CadesVerification, Indication, PdfVerification  # noqa: E402
from berigna.core.verification import Verification, is_detached, original_of  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.i18n import N_, _, catalogue, current_language  # noqa: E402
from berigna.ui.widgets import brand_markup, named, show_in_spanish, spanish_button  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow

log = logging.getLogger(__name__)

# Verifies the bytes of a signed document of a kind, with the file a detached signature signs
# (or None); returns the result and the trust store it used.
Verify = Callable[[bytes, bytes | None, DocumentKind], tuple[Verification, TrustStore]]

REPORTS = {
    # kind: (suggested file name, language of a PDF report or None for JSON)
    "pdf-es": (N_("{stem} - verification report.pdf"), Language.ES_PE),
    "pdf-quz": (N_("{stem} - verification report (Quechua).pdf"), Language.QUZ_PE),
    "json": (N_("{stem} - verification report.json"), None),
}
SIGNED_VERSION = N_("{stem} - signed version {number}.pdf")


def content_name(signature: Path) -> str:
    """The name to save the content of a ``.p7m`` under: the name without ``.p7m``."""
    return signature.stem if signature.suffix.lower() == ".p7m" else f"{signature.name}.bin"


class VerificationPage:
    def __init__(self, window: "MainWindow", document: DocumentInfo, verify: Verify) -> None:
        self._window = window
        self.document = document
        self._verify = verify
        self.verification: Verification | None = None
        self._store: TrustStore | None = None
        self._data = b""
        self._sha256 = ""
        # The file a detached signature signs (RF-051): found next to it, or chosen.
        self.original: Path | None = None
        self._original_sha256 = ""
        self._existing_problems = False
        self.spanish_dialog: Adw.AlertDialog | None = None

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
            ("choose-original", None, lambda *_args: self._choose_original()),
            ("save-content", None, lambda *_args: self._on_save_content()),
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
        path, kind = self.document.path, self.document.kind

        def work() -> None:
            try:
                data = path.read_bytes()
                content = None
                if is_detached(data, kind):
                    original = self.original or original_of(path, data)
                    if original is None:
                        GLib.idle_add(self._ask_original)
                        return
                    content = original.read_bytes()
                    GLib.idle_add(self._set_original, original, content)
                verification, store = self._verify(data, content, kind)
                GLib.idle_add(self._show_result, data, verification, store)
            except BerignaError as exc:
                GLib.idle_add(self._show_error, explain_error(exc.code, catalogue()) or "")
            except OSError as exc:
                name = Path(exc.filename).name if exc.filename else path.name
                GLib.idle_add(self._show_error, _("{name} could not be opened.").format(name=name))
            except Exception:  # never leave the spinner turning: unexpected error (ERR-000)
                log.exception("verification failed")
                GLib.idle_add(self._show_error, explain_error("ERR-000", catalogue()) or "")

        threading.Thread(target=work, name="berigna-verify", daemon=True).start()

    def _set_original(self, original: Path, content: bytes) -> bool:
        self.original = original
        self._original_sha256 = hashlib.sha256(content).hexdigest()
        return GLib.SOURCE_REMOVE

    def _ask_original(self) -> bool:
        """A detached signature without its file next to it: ask for it (RF-051)."""
        if not self.current:
            return GLib.SOURCE_REMOVE
        page = Adw.StatusPage(
            icon_name="document-open-symbolic",
            title=_("Choose the signed file"),
            description=_(
                "{name} is a detached signature: the file it signs is not next to it with "
                "the same name. Choose that file to verify the signature."
            ).format(name=self.document.path.name),
        )
        button = Gtk.Button(
            label=_("_Choose File…"),
            use_underline=True,
            halign=Gtk.Align.CENTER,
            action_name="verification.choose-original",
        )
        button.add_css_class("pill")
        button.add_css_class("suggested-action")
        page.set_child(button)
        self._replace("original", page)
        return GLib.SOURCE_REMOVE

    def _choose_original(self) -> None:
        folder = Gio.File.new_for_path(str(self.document.path.parent))
        dialog = Gtk.FileDialog(title=_("Choose the Signed File"), initial_folder=folder)

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                path = dialog.open_finish(result).get_path()
            except GLib.Error:  # dismissed by the user
                return
            if path is not None:
                self.verify_with(Path(path))

        dialog.open(self._window.window, None, chosen)

    def verify_with(self, original: Path) -> None:
        """Verify the detached signature against ``original``, which the user chose."""
        self.original = original
        self.start()

    def _show_error(self, message: str) -> bool:
        if self.current:
            error = Adw.StatusPage(
                icon_name="dialog-error-symbolic",
                title=_("The document could not be verified"),
                description=brand_markup(message),
            )
            self._replace("error", error)
        return GLib.SOURCE_REMOVE

    def _record(self, verification: Verification) -> None:
        """RF-082: the worst indication of the document and how many signatures passed."""
        services = self._window.services
        history = services.history()
        if history is None:
            return
        indications = [s.indication for s in verification.signatures]
        indications += [t.indication for t in presentation.document_timestamps(verification)]
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

    def _show_result(self, data: bytes, verification: Verification, store: TrustStore) -> bool:
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
            self.summary_row.add_suffix(spanish_button(self.show_spanish, valign=Gtk.Align.CENTER))
        summary.add(self.summary_row)
        for row in self._file_rows(verification):
            summary.add(row)
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
        # Adding a signature: to a PDF (CU-03) and to an XML document (CU-05); a CAdES
        # countersignature (RF-023) comes after 1.0, and signing a detached signature would
        # sign the signature file, not the document it covers.
        self._sign.set_visible(self.document.kind is not DocumentKind.CADES and not self.original)
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
        body = presentation.verification_text(view, spanish)
        self.spanish_dialog = show_in_spanish(self._window.window, self.document.path.name, body)
        return self.spanish_dialog

    def _file_rows(self, verification: Verification) -> list[Adw.ActionRow]:
        """The file a detached signature signs, which the user can change, and the content of
        a ``.p7m``, which the user can save (RF-051)."""
        rows = []
        if self.original is not None:
            row = Adw.ActionRow(
                title=_("Signed file"),
                subtitle=self.original.name,
                subtitle_selectable=True,
                use_markup=False,
            )
            row.add_css_class("property")
            change = named(
                Gtk.Button(
                    icon_name="document-open-symbolic",
                    tooltip_text=_("Choose Another File"),
                    valign=Gtk.Align.CENTER,
                    action_name="verification.choose-original",
                )
            )
            change.add_css_class("flat")
            row.add_suffix(change)
            rows.append(row)
        if isinstance(verification, CadesVerification) and verification.content is not None:
            row = Adw.ActionRow(
                title=_("Save the Signed Content"),
                subtitle=_("The file inside the signature, as it was signed"),
                use_markup=False,
            )
            save = named(
                Gtk.Button(
                    icon_name="document-save-symbolic",
                    tooltip_text=_("Save the Signed Content"),
                    valign=Gtk.Align.CENTER,
                    action_name="verification.save-content",
                )
            )
            save.add_css_class("flat")
            row.add_suffix(save)
            rows.append(row)
        return rows

    def _result_group(self, view: presentation.ResultView, number: int) -> Adw.PreferencesGroup:
        group = Adw.PreferencesGroup(title=view.title, description=brand_markup(view.explanation))
        group.set_header_suffix(_icon(view.icon, view.style))
        expander = _details(view, title=_("Technical Details"))
        if view.signed_revision_length is None:  # only a PDF keeps earlier versions
            group.add(expander)
            return group
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
        signed_file = (
            (self.original.name, self._original_sha256) if self.original is not None else None
        )
        if language is None:
            data = report_data(
                self.verification,
                file_name=name,
                file_sha256=digest,
                store=self._store,
                signed_file=signed_file,
            )
            return dumps(data).encode()
        return pdf_report(
            self.verification,
            file_name=name,
            file_sha256=digest,
            store=self._store,
            language=language,
            signed_file=signed_file,
        )

    def signed_revision(self, number: int) -> bytes:
        """The document as signature ``number`` (from 1) left it (CU-06)."""
        if not isinstance(self.verification, PdfVerification):
            raise RuntimeError("no verification result of a PDF")
        length = self.verification.signatures[number - 1].signed_revision_length
        return self._data[:length]

    def signed_content(self) -> bytes:
        """The file inside a ``.p7m``, as it was signed (RF-051)."""
        if not isinstance(self.verification, CadesVerification):
            raise RuntimeError("no CAdES verification result")
        if self.verification.content is None:  # an empty file is content too
            raise RuntimeError("a detached signature carries no content")
        return self.verification.content

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

    def _on_save_content(self) -> None:
        self._ask_path(content_name(self.document.path), lambda _path: self.signed_content())

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
