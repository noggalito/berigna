# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Main window: start page, opened document and the DNIe status bar (BRG-UX-001 §3.1)."""

import threading
from collections.abc import Callable, Sequence
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from berigna.core.documents import DocumentInfo, DocumentKind, inspect_document  # noqa: E402
from berigna.core.errors import BerignaError  # noqa: E402
from berigna.core.i18n import Language, translations  # noqa: E402
from berigna.core.report import messages  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.token.monitor import DeviceStatus  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.i18n import _, catalogue, current_language, translate_view  # noqa: E402
from berigna.ui.signing import SigningPage, SigningServices  # noqa: E402
from berigna.ui.verification import VerificationPage, Verify  # noqa: E402
from berigna.ui.widgets import brand_markup  # noqa: E402

VIEW = "/com/noggalito/Berigna/ui/window.ui"


class MainWindow:
    """Wraps the window built from the view; the application rebuilds it to change language."""

    def __init__(
        self, application: Adw.Application, verify: Verify, signing: SigningServices
    ) -> None:
        view = Gio.resources_lookup_data(VIEW, Gio.ResourceLookupFlags.NONE).get_data()
        builder = Gtk.Builder()
        builder.add_from_string(translate_view(view))
        self.window: Adw.ApplicationWindow = builder.get_object("window")
        self.window.set_application(application)
        self._verify = verify
        self._signing = signing
        self._toasts: Adw.ToastOverlay = builder.get_object("toasts")
        self._navigation: Adw.NavigationView = builder.get_object("navigation")
        self._status_icon: Gtk.Image = builder.get_object("status_icon")
        self._status_label: Gtk.Label = builder.get_object("status_label")
        self._banner: Adw.Banner = builder.get_object("unreviewed_banner")
        self._setup_banner(self._banner)
        self.document: DocumentInfo | None = None
        self.verification: VerificationPage | None = None
        self.signing: SigningPage | None = None

        open_action = Gio.SimpleAction.new("open", None)
        open_action.connect("activate", lambda *_args: self._choose_file())
        self.window.add_action(open_action)

        drop = Gtk.DropTarget.new(Gdk.FileList, Gdk.DragAction.COPY)
        drop.connect("drop", self._on_drop)
        self.window.add_controller(drop)
        self.show_device_status(None)

    def _setup_banner(self, banner: Adw.Banner) -> None:
        quechua = current_language() is Language.QUZ_PE
        banner.set_revealed(quechua)
        if quechua:
            texts = [
                translations(language).gettext(messages.UNREVIEWED_TRANSLATION)
                for language in (Language.QUZ_PE, Language.ES_PE)
            ]
            banner.set_title(" · ".join(dict.fromkeys(texts)))
            banner.set_button_label(_("Show in Spanish"))
            banner.set_action_name("app.show-in-spanish")

    def page(
        self, title: str, tag: str, content: Gtk.Widget, end: Sequence[Gtk.Widget] = ()
    ) -> Adw.NavigationPage:
        """A document page: header bar with the back button and ``end`` widgets, the Quechua
        notice and ``content``."""
        header = Adw.HeaderBar()
        for widget in end:
            header.pack_end(widget)
        banner = Adw.Banner()
        self._setup_banner(banner)
        view = Adw.ToolbarView(content=content)
        view.add_top_bar(header)
        view.add_top_bar(banner)
        return Adw.NavigationPage(title=title, tag=tag, child=view)

    def show_page(self, page: Adw.NavigationPage) -> None:
        # replace(), not pop and push: a page being popped keeps its tag while it animates.
        self._navigation.replace([self._navigation.find_page("start"), page])

    def sign(self, document: DocumentInfo, *, existing_problems: bool = False) -> None:
        """Open the signing page; over the verification page when the PDF is signed (CU-03)."""
        try:
            self.signing = SigningPage(
                self, document, self._signing, existing_problems=existing_problems
            )
        except OSError:
            self.toast(_("{name} could not be opened.").format(name=document.path.name))
            return
        if self.verification is not None:
            self._navigation.push(self.signing.page)
        else:
            self.show_page(self.signing.page)

    def show_device_status(self, status: DeviceStatus | None) -> None:
        view = presentation.device_status(status)
        self._status_icon.set_from_icon_name(view.icon)
        self._status_label.set_label(view.message)

    def toast(self, message: str) -> None:
        self._toasts.add_toast(Adw.Toast.new(brand_markup(message)))

    def _choose_file(self) -> None:
        pdf = Gtk.FileFilter()
        pdf.set_name(_("PDF documents"))
        pdf.add_mime_type("application/pdf")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(pdf)
        dialog = Gtk.FileDialog(title=_("Open Document"), filters=filters, default_filter=pdf)
        dialog.open(self.window, None, self._on_file_chosen)

    def _on_file_chosen(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            file = dialog.open_finish(result)
        except GLib.Error:  # dismissed by the user
            return
        self.open_file(file)

    def _on_drop(self, _target: Gtk.DropTarget, files: Gdk.FileList, _x: float, _y: float) -> bool:
        dropped = files.get_files()
        if dropped:
            self.open_file(dropped[0])
        return bool(dropped)

    def open_file(self, file: Gio.File, on_done: Callable[[], None] | None = None) -> None:
        """Inspect ``file`` in a worker thread and show it; ``on_done`` runs afterwards."""
        path = file.get_path()
        if path is None:  # not a local file (for instance, a remote location)
            self.toast(_("Only files on this computer can be opened."))
            return

        def work() -> None:
            outcome: DocumentInfo | BaseException
            try:
                outcome = inspect_document(Path(path))
            except (OSError, BerignaError) as exc:
                outcome = exc
            GLib.idle_add(self._show_document, Path(path), outcome, on_done)

        threading.Thread(target=work, name="berigna-open", daemon=True).start()

    def _show_document(
        self,
        path: Path,
        outcome: DocumentInfo | BaseException,
        on_done: Callable[[], None] | None,
    ) -> bool:
        if isinstance(outcome, DocumentInfo):
            self.document = outcome
            self.verification = self.signing = None
            if outcome.kind is DocumentKind.PDF and outcome.signed:
                self.verification = VerificationPage(self, outcome, self._verify)
                self.show_page(self.verification.page)
            elif outcome.kind is DocumentKind.PDF:
                self.sign(outcome)
            else:  # CAdES and XAdES come in Phase 4
                status = Adw.StatusPage(
                    icon_name="x-office-document-symbolic",
                    title=path.name,
                    description=brand_markup(presentation.document_summary(outcome)),
                )
                self.show_page(self.page(path.name, "document", status))
        elif isinstance(outcome, BerignaError):
            reason = explain_error(outcome.code, catalogue()) or ""
            self.toast(f"{path.name}: {reason}")
        else:
            self.toast(_("{name} could not be opened.").format(name=path.name))
        if on_done is not None:
            on_done()
        return GLib.SOURCE_REMOVE
