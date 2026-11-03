# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing several files with one PIN (CU-04; RF-040 to RF-043; BRG-UX-001 §3.4).

The list the user builds is the confirmation: what is signed is each file as it was when it
was added (its SHA-256, RF-018), and the PIN dialog says how many documents it covers. Each
file is signed in the format of its kind (RF-041): PAdES for PDF, XAdES for XML and CAdES for
the rest, in the packagings the user chooses for XML and for the rest. The core
(:func:`berigna.core.batch.sign_batch`) runs in a worker thread; the user can cancel between
files. The signatures of a batch are not visible.
"""

import logging
import threading
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from berigna.core.batch import (  # noqa: E402
    BatchItem,
    Outcome,
    batch_outputs,
    collect_files,
    is_signature,
    read_files,
    sign_batch,
)
from berigna.core.documents import DocumentKind  # noqa: E402
from berigna.core.errors import BerignaError, PinIncorrectError  # noqa: E402
from berigna.core.files import dated_name, write_atomically  # noqa: E402
from berigna.core.formats.cades import CadesPackaging  # noqa: E402
from berigna.core.formats.pades import SignatureLevel  # noqa: E402
from berigna.core.formats.xades import XadesPackaging  # noqa: E402
from berigna.core.history import Kind  # noqa: E402
from berigna.core.report.batch_report import batch_csv  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.signing import Packaging, SigningJob  # noqa: E402
from berigna.core.token.pin import Pin  # noqa: E402
from berigna.core.validation import SignerCheck  # noqa: E402
from berigna.ui import presentation  # noqa: E402
from berigna.ui.i18n import _, catalogue, current_language, ngettext  # noqa: E402
from berigna.ui.signing import (  # noqa: E402
    LevelChoice,
    PinDialog,
    SignatureData,
    SigningServices,
    ask_pin_in_main_loop,
    failure_page,
    output_settings,
    signature_entry,
)
from berigna.ui.widgets import brand_markup, document_filters, label_factory, named  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow

log = logging.getLogger(__name__)

_ICONS = {
    Outcome.SIGNED: ("object-select-symbolic", "success"),
    Outcome.FAILED: ("dialog-error-symbolic", "error"),
    Outcome.SKIPPED: ("action-unavailable-symbolic", "dimmed"),
}


def display_folder(folder: Path) -> str:
    """The folder as the user knows it: "~/Documentos" rather than "/home/rosa/Documentos"."""
    home = Path.home()
    return f"~/{folder.relative_to(home)}" if folder.is_relative_to(home) else str(folder)


class FormatChoices:
    """The packaging of the XML documents and of the other files of a batch (RF-041): XAdES
    enveloped and CAdES detached unless the user chooses otherwise. Each row shows only when
    the list has files of its kind."""

    XML = (XadesPackaging.ENVELOPED, XadesPackaging.ENVELOPING, XadesPackaging.DETACHED)
    OTHER = (CadesPackaging.DETACHED, CadesPackaging.ENVELOPING)

    def __init__(self) -> None:
        self.group = Adw.PreferencesGroup(
            title=_("Signature Format"),
            description=_("PDF documents are signed in PAdES."),
        )
        self.xml = self._combo(_("XML Documents"), self.XML)
        self.other = self._combo(_("Other Files"), self.OTHER)

    def _combo(
        self, title: str, packagings: tuple[CadesPackaging | XadesPackaging, ...]
    ) -> Adw.ComboRow:
        labels = [presentation.packaging_title(packaging) for packaging in packagings]
        combo = Adw.ComboRow(
            title=title,
            model=Gtk.StringList.new(labels),
            factory=label_factory(visible=False),
            list_factory=label_factory(visible=True),
            subtitle_lines=0,
            use_markup=False,  # translated free text in the subtitle
        )

        def describe(*_args: object) -> None:
            selected = combo.get_selected()
            # the label, and how the variant differs from Firma Perú (BRG-UX-001 §3.2)
            note = presentation.packaging_note(packagings[selected])
            combo.set_subtitle(f"{labels[selected]}\n{note}" if note else labels[selected])

        combo.connect("notify::selected", describe)
        describe()
        self.group.add(combo)
        return combo

    def show_for(self, kinds: set[DocumentKind]) -> None:
        xml, other = DocumentKind.XML in kinds, bool(kinds - {DocumentKind.PDF, DocumentKind.XML})
        self.xml.set_visible(xml)
        self.other.set_visible(other)
        self.group.set_visible(xml or other)

    def packaging(self, kind: DocumentKind) -> Packaging:
        """How a file of ``kind`` is signed: None (PAdES) for a PDF."""
        if kind is DocumentKind.PDF:
            return None
        if kind is DocumentKind.XML:
            return self.XML[self.xml.get_selected()]
        return self.OTHER[self.other.get_selected()]


class BatchPage:
    """The list of documents, the level and the signature data, and the batch flow."""

    def __init__(
        self, window: "MainWindow", services: SigningServices, paths: Sequence[Path]
    ) -> None:
        self._window = window
        self._services = services
        self.files: list[tuple[Path, str, DocumentKind]] = []  # path, SHA-256 when added, kind
        self.items: list[BatchItem] | None = None
        self.pin_dialog: PinDialog | None = None
        self._remaining_tries: int | None = None
        self._cancel = threading.Event()
        self._check: SignerCheck | None = None  # set when the PIN is asked
        self._adding = 0  # workers still reading files to add

        self._sign = Gtk.Button(label=_("_Sign"), use_underline=True, sensitive=False)
        self._sign.add_css_class("suggested-action")
        self._sign.connect("clicked", lambda _b: self.start())

        self._stack = Gtk.Stack()
        self._stack.add_named(self._form(), "form")
        self._stack.add_named(self._busy(), "busy")
        self.page = window.page(_("Sign Several Documents"), "batch", self._stack, [self._sign])
        self.add_paths(paths)

    # -- Form ----------------------------------------------------------------------------------

    def _form(self) -> Gtk.Widget:
        panel = Adw.PreferencesPage()
        buttons = Gtk.Box(spacing=6)
        for icon, tooltip, callback in (
            ("list-add-symbolic", _("Add Documents"), self._choose_files),
            ("folder-open-symbolic", _("Add Folder"), self._choose_folder),
        ):
            button = named(
                Gtk.Button(icon_name=icon, tooltip_text=tooltip, valign=Gtk.Align.CENTER)
            )
            button.add_css_class("flat")
            button.connect("clicked", lambda _b, c=callback: c())
            buttons.append(button)
        self.files_group = Adw.PreferencesGroup(title=_("Documents"), header_suffix=buttons)
        self.recursive = Adw.SwitchRow(title=_("Include Subfolders When Adding a Folder"))
        self.files_group.add(self.recursive)
        self._rows: list[Adw.ActionRow] = []
        panel.add(self.files_group)

        self.formats = FormatChoices()
        panel.add(self.formats.group)
        self.levels = LevelChoice(self._services)
        panel.add(self.levels.group)
        self.signature_data = SignatureData(self._services.settings)
        panel.add(self.signature_data.group)
        clamp = Adw.Clamp(maximum_size=720, child=panel)
        return clamp

    def add_paths(self, paths: Iterable[Path]) -> None:
        """Add the files among ``paths``; those already listed, or that cannot be read, are
        left out.

        Reading and hashing a folder of large files takes a while: it runs in a worker
        thread, with the Sign button off until it is done."""
        paths = list(paths)
        recursive = self.recursive.get_active()
        self._adding += 1
        self._sign.set_sensitive(False)

        def work() -> None:
            signatures = sum(1 for p in paths if p.is_file() and is_signature(p))
            hashed, left_out = read_files(collect_files(paths, recursive=recursive))
            left_out += sum(1 for p in paths if not p.is_dir() and not p.is_file())
            GLib.idle_add(self._added, hashed, left_out, signatures)

        threading.Thread(target=work, name="berigna-batch-add", daemon=True).start()

    def _added(
        self, hashed: list[tuple[Path, str, DocumentKind]], left_out: int, signatures: int = 0
    ) -> bool:
        self._adding -= 1
        listed = {path for path, _sha, _kind in self.files}
        for path, sha, kind in hashed:
            if path not in listed:
                self.files.append((path, sha, kind))
                listed.add(path)
        if left_out:
            self._window.toast(
                ngettext(
                    "{n} file cannot be read; it was left out.",
                    "{n} files cannot be read; they were left out.",
                    left_out,
                ).format(n=left_out)
            )
        if signatures:
            self._window.toast(
                ngettext(
                    "{n} signature was left out: open it on its own to verify it.",
                    "{n} signatures were left out: open them one by one to verify them.",
                    signatures,
                ).format(n=signatures)
            )
        self._show_files()
        return GLib.SOURCE_REMOVE

    def remove(self, path: Path) -> None:
        self.files = [file for file in self.files if file[0] != path]
        self._show_files()

    def _show_files(self) -> None:
        for row in self._rows:
            self.files_group.remove(row)
        self._rows = []
        for path, _sha, kind in self.files:
            row = Adw.ActionRow(
                title=path.name,
                subtitle=f"{display_folder(path.parent)} · {_format_name(kind)}",
                use_markup=False,
            )
            remove = named(
                Gtk.Button(
                    icon_name="list-remove-symbolic",
                    tooltip_text=_("Remove from the List"),
                    valign=Gtk.Align.CENTER,
                )
            )
            remove.add_css_class("flat")
            remove.connect("clicked", lambda _b, p=path: self.remove(p))
            row.add_suffix(remove)
            self.files_group.add(row)
            self._rows.append(row)
        count = len(self.files)
        self.formats.show_for({kind for _path, _sha, kind in self.files})
        self.files_group.set_description(
            ngettext(
                "{n} document. They are signed with a single PIN; the signatures are not visible.",
                "{n} documents. They are signed with a single PIN; the signatures are not visible.",
                count,
            ).format(n=count)
        )
        self._sign.set_label(
            ngettext("_Sign {n} Document", "_Sign {n} Documents", count).format(n=count)
        )
        self._sign.set_sensitive(count > 0 and not self._adding)

    def _choose_files(self) -> None:
        filters = document_filters()
        dialog = Gtk.FileDialog(
            title=_("Add Documents"), filters=filters, default_filter=filters.get_item(0)
        )

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                files = dialog.open_multiple_finish(result)
            except GLib.Error:  # dismissed by the user
                return
            self.add_paths(_local_paths(files))

        dialog.open_multiple(self._window.window, None, chosen)

    def _choose_folder(self) -> None:
        dialog = Gtk.FileDialog(title=_("Add Folder"))

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                folder = dialog.select_folder_finish(result)
            except GLib.Error:
                return
            self.add_paths(_local_paths([folder]))

        dialog.select_folder(self._window.window, None, chosen)

    # -- Flow ----------------------------------------------------------------------------------

    def _busy(self) -> Gtk.Widget:
        self._busy_page = Adw.StatusPage(paintable=Adw.SpinnerPaintable())
        self._busy_page.get_paintable().set_widget(self._busy_page)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18, halign=Gtk.Align.CENTER)
        self.progress = Gtk.ProgressBar(show_text=True, width_request=320)
        self._cancel_button = Gtk.Button(label=_("_Cancel"), use_underline=True)
        self._cancel_button.add_css_class("pill")
        self._cancel_button.connect("clicked", lambda _b: self.cancel())
        box.append(self.progress)
        box.append(self._cancel_button)
        self._busy_page.set_child(box)
        return self._busy_page

    def _set_busy(self, title: str, signing: bool = False) -> bool:
        self._busy_page.set_title(title)
        self.progress.set_visible(signing)
        self._cancel_button.set_visible(signing)
        self._cancel_button.set_sensitive(True)
        self._stack.set_visible_child_name("busy")
        self._sign.set_sensitive(False)
        return GLib.SOURCE_REMOVE

    def cancel(self) -> None:
        """Stop after the document being signed (RF-043)."""
        self._cancel.set()
        self._cancel_button.set_sensitive(False)
        self._busy_page.set_title(_("Cancelling after the current document…"))

    def _back_to_form(self) -> None:
        self._stack.set_visible_child_name("form")
        self._sign.set_visible(True)
        self._sign.set_sensitive(bool(self.files))

    def _show(self, name: str, child: Gtk.Widget) -> None:
        old = self._stack.get_child_by_name(name)
        if old is not None:
            self._stack.remove(old)
        self._stack.add_named(child, name)
        self._stack.set_visible_child_name(name)

    def start(self, level: SignatureLevel | None = None) -> None:
        if self._adding or not self.files:  # the list is not settled yet
            return
        level = level or self.levels.level
        self.signature_data.remember()
        options = self.signature_data.options()
        suffix, directory = output_settings(self._services.settings)
        packagings = [self.formats.packaging(kind) for _path, _sha, kind in self.files]
        outputs = batch_outputs(
            [path for path, _sha, _kind in self.files], suffix, directory, packagings
        )
        jobs = [
            SigningJob(path, output, sha, packaging)
            for (path, sha, _kind), output, packaging in zip(
                self.files, outputs, packagings, strict=True
            )
        ]
        self._cancel.clear()
        self._set_busy(_("Checking your certificate…"))
        services = self._services

        def work() -> None:
            try:
                with services.open_token() as token:
                    items = sign_batch(
                        jobs,
                        token=token,
                        store=services.trust_store(),
                        ask_pin=lambda check: self._ask_pin(check, level, len(jobs)),
                        options=options,
                        level=level,
                        timestamper=services.timestamper(),
                        online=services.online,
                        cancelled=self._cancel.is_set,
                        progress=lambda done, total, _item: GLib.idle_add(
                            self._progress, done, total
                        ),
                    )
            except BerignaError as exc:
                GLib.idle_add(self._failed, exc, level)
            except Exception:  # never leave the page waiting (ERR-000)
                log.exception("batch signing failed")
                GLib.idle_add(self._failed, None, level)
            else:
                GLib.idle_add(self._done, items, level)

        threading.Thread(target=work, name="berigna-batch", daemon=True).start()

    def _ask_pin(self, check: SignerCheck, level: SignatureLevel, count: int) -> Pin | None:
        self._check = check

        def dialog(reply: Callable[[Pin | None], None]) -> PinDialog:
            self.pin_dialog = PinDialog(count, check, level, self._remaining_tries, reply)
            return self.pin_dialog

        def signing() -> None:
            GLib.idle_add(self._progress, 0, count)

        return ask_pin_in_main_loop(self._window, dialog, signing)

    def _progress(self, done: int, total: int) -> bool:
        if not self._cancel.is_set():
            self._set_busy(
                _("Signing {done} of {total} with your DNIe…").format(
                    done=min(done + 1, total), total=total
                ),
                signing=True,
            )
        self.progress.set_fraction(done / total if total else 0)
        self.progress.set_text(f"{done} / {total}")
        return GLib.SOURCE_REMOVE

    def _failed(self, error: BerignaError | None, level: SignatureLevel) -> bool:
        if isinstance(error, PinIncorrectError) and error.remaining_tries != 0:
            self._remaining_tries = error.remaining_tries
        page = failure_page(
            self._window,
            error,
            level,
            title=_("The documents were not signed"),
            back=self._back_to_form,
            retry=self.start,
        )
        if page is not None:
            self._show("error", page)
        return GLib.SOURCE_REMOVE

    def _record(self, items: list[BatchItem], level: SignatureLevel) -> None:
        """RF-082: one history row per document of the batch, also those left unsigned when
        it was cancelled or stopped (what was not done is part of the record)."""
        check, history = self._check, self._services.history()
        if check is None or history is None:
            return
        for item in items:
            self._services.record(
                signature_entry(
                    Kind.BATCH,
                    history.name(item.job.source),
                    item.job.expected_sha256,
                    check,
                    item.result,
                    item.code,
                    level,
                )
            )

    def _done(self, items: list[BatchItem], level: SignatureLevel) -> bool:
        self._record(items, level)
        self.items = items
        self._remaining_tries = None
        signed = sum(item.outcome is Outcome.SIGNED for item in items)
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(
            title=ngettext(
                "{signed} of {total} document signed",
                "{signed} of {total} documents signed",
                len(items),
            ).format(signed=signed, total=len(items))
        )
        for item in items:
            icon, style = _ICONS[item.outcome]
            if item.result is not None:
                subtitle = item.result.output.name
            else:
                subtitle = explain_error(item.code or "ERR-000", catalogue()) or ""
            row = Adw.ActionRow(
                title=item.job.source.name, subtitle=brand_markup(subtitle), subtitle_lines=0
            )
            image = Gtk.Image(icon_name=icon)
            image.add_css_class(style)
            row.add_prefix(image)
            group.add(row)
        page.add(group)

        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.CENTER, margin_top=12)
        for label, callback, enabled in (
            (_("_Export Report…"), self._export, True),
            (_("Show in _Folder"), self._show_in_folder, signed > 0),
            (_("Sign _Other Documents"), self._again, True),
        ):
            button = Gtk.Button(label=label, use_underline=True, sensitive=enabled)
            button.add_css_class("pill")
            button.connect("clicked", lambda _b, c=callback: c())
            buttons.append(button)
        page.add(_group_with(buttons))
        self._sign.set_visible(False)
        self._show("done", Adw.Clamp(maximum_size=720, child=page))
        return GLib.SOURCE_REMOVE

    # -- After signing -------------------------------------------------------------------------

    def report(self) -> str:
        return batch_csv(self.items or [], current_language())

    def _export(self) -> None:
        dialog = Gtk.FileDialog(
            title=_("Export Report"), initial_name=dated_name(_("batch-report.csv"))
        )

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                file = dialog.save_finish(result)
            except GLib.Error:
                return
            path = file.get_path()
            if path is None:
                return
            try:
                write_atomically(Path(path), self.report().encode("utf-8"), replace=True)
            except OSError:
                self._window.toast(_("The report could not be saved."))
            else:
                self._window.toast(_("Report saved."))

        dialog.save(self._window.window, None, chosen)

    def _show_in_folder(self) -> None:
        signed = [item.result for item in self.items or [] if item.result is not None]
        if signed:
            file = Gio.File.new_for_path(str(signed[0].output))
            Gtk.FileLauncher(file=file).open_containing_folder(self._window.window, None, None)

    def _again(self) -> None:
        """Back to the list: the signed documents leave it, the others stay."""
        signed = {item.job.source for item in self.items or [] if item.outcome is Outcome.SIGNED}
        self.files = [file for file in self.files if file[0] not in signed]
        self.items = None
        self._show_files()
        self._back_to_form()


def _format_name(kind: DocumentKind) -> str:
    return {DocumentKind.PDF: "PAdES", DocumentKind.XML: "XAdES"}.get(kind, "CAdES")


def _local_paths(files: Iterable[Gio.File]) -> list[Path]:
    return [Path(path) for file in files if (path := file.get_path()) is not None]


def _group_with(widget: Gtk.Widget) -> Adw.PreferencesGroup:
    group = Adw.PreferencesGroup()
    group.add(widget)
    return group
