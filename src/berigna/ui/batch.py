# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Signing several PDFs with one PIN (CU-04; RF-040 to RF-043; BRG-UX-001 §3.4).

The list the user builds is the confirmation: what is signed is each file as it was when it
was added (its SHA-256, RF-018), and the PIN dialog says how many documents it covers. The
core (:func:`berigna.core.batch.sign_pdf_batch`) runs in a worker thread; the user can cancel
between files. The signatures of a batch are not visible.
"""

import hashlib
import logging
import threading
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from berigna.core.batch import BatchItem, Outcome, batch_outputs, sign_pdf_batch  # noqa: E402
from berigna.core.errors import BerignaError, PinIncorrectError  # noqa: E402
from berigna.core.files import write_atomically  # noqa: E402
from berigna.core.formats.pades import SignatureLevel  # noqa: E402
from berigna.core.history import Kind  # noqa: E402
from berigna.core.report.batch_report import batch_csv  # noqa: E402
from berigna.core.report.explanations import explain_error  # noqa: E402
from berigna.core.signing import SigningJob  # noqa: E402
from berigna.core.token.pin import Pin  # noqa: E402
from berigna.core.validation import SignerCheck  # noqa: E402
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
from berigna.ui.widgets import brand_markup  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow

log = logging.getLogger(__name__)

_ICONS = {
    Outcome.SIGNED: ("object-select-symbolic", "success"),
    Outcome.FAILED: ("dialog-error-symbolic", "error"),
    Outcome.SKIPPED: ("action-unavailable-symbolic", "dimmed"),
}


def is_pdf(path: Path) -> bool:
    return path.suffix.lower() == ".pdf"


def display_folder(folder: Path) -> str:
    """The folder as the user knows it: "~/Documentos" rather than "/home/rosa/Documentos"."""
    home = Path.home()
    return f"~/{folder.relative_to(home)}" if folder.is_relative_to(home) else str(folder)


def collect_pdfs(paths: Iterable[Path], *, recursive: bool) -> list[Path]:
    """The PDFs among ``paths``: files as given, folders expanded (with their subfolders when
    ``recursive``), in name order, each once (RF-041)."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            pattern = path.rglob("*") if recursive else path.glob("*")
            found += sorted(p for p in pattern if p.is_file() and is_pdf(p))
        elif is_pdf(path):
            found.append(path)
    return list(dict.fromkeys(found))


class BatchPage:
    """The list of documents, the level and the signature data, and the batch flow."""

    def __init__(
        self, window: "MainWindow", services: SigningServices, paths: Sequence[Path]
    ) -> None:
        self._window = window
        self._services = services
        self.files: list[tuple[Path, str]] = []  # path and SHA-256 when added
        self.items: list[BatchItem] | None = None
        self.pin_dialog: PinDialog | None = None
        self._remaining_tries: int | None = None
        self._cancel = threading.Event()
        self._check: SignerCheck | None = None  # set when the PIN is asked

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
            button = Gtk.Button(icon_name=icon, tooltip_text=tooltip, valign=Gtk.Align.CENTER)
            button.add_css_class("flat")
            button.connect("clicked", lambda _b, c=callback: c())
            buttons.append(button)
        self.files_group = Adw.PreferencesGroup(title=_("Documents"), header_suffix=buttons)
        self.recursive = Adw.SwitchRow(title=_("Include Subfolders When Adding a Folder"))
        self.files_group.add(self.recursive)
        self._rows: list[Adw.ActionRow] = []
        panel.add(self.files_group)

        self.levels = LevelChoice(self._services)
        panel.add(self.levels.group)
        self.signature_data = SignatureData(self._services.settings)
        panel.add(self.signature_data.group)
        clamp = Adw.Clamp(maximum_size=720, child=panel)
        return clamp

    def add_paths(self, paths: Iterable[Path]) -> None:
        """Add the PDFs among ``paths``; others, and those already listed, are left out."""
        listed = {path for path, _sha in self.files}
        left_out = 0
        for path in collect_pdfs(paths, recursive=self.recursive.get_active()):
            if path in listed:
                continue
            try:
                sha = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                left_out += 1
                continue
            self.files.append((path, sha))
            listed.add(path)
        others = [p for p in paths if not p.is_dir() and not is_pdf(p)]
        left_out += len(others)
        if left_out:
            self._window.toast(
                ngettext(
                    "{n} file is not a PDF or cannot be read; it was left out.",
                    "{n} files are not PDFs or cannot be read; they were left out.",
                    left_out,
                ).format(n=left_out)
            )
        self._show_files()

    def remove(self, path: Path) -> None:
        self.files = [(p, sha) for p, sha in self.files if p != path]
        self._show_files()

    def _show_files(self) -> None:
        for row in self._rows:
            self.files_group.remove(row)
        self._rows = []
        for path, _sha in self.files:
            row = Adw.ActionRow(
                title=path.name, subtitle=display_folder(path.parent), use_markup=False
            )
            remove = Gtk.Button(
                icon_name="list-remove-symbolic",
                tooltip_text=_("Remove from the List"),
                valign=Gtk.Align.CENTER,
            )
            remove.add_css_class("flat")
            remove.connect("clicked", lambda _b, p=path: self.remove(p))
            row.add_suffix(remove)
            self.files_group.add(row)
            self._rows.append(row)
        count = len(self.files)
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
        self._sign.set_sensitive(count > 0)

    def _choose_files(self) -> None:
        pdf = Gtk.FileFilter()
        pdf.set_name(_("PDF documents"))
        pdf.add_mime_type("application/pdf")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(pdf)
        dialog = Gtk.FileDialog(title=_("Add Documents"), filters=filters, default_filter=pdf)

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
        level = level or self.levels.level
        self.signature_data.remember()
        options = self.signature_data.options()
        suffix, directory = output_settings(self._services.settings)
        outputs = batch_outputs([path for path, _sha in self.files], suffix, directory)
        jobs = [
            SigningJob(path, output, sha)
            for (path, sha), output in zip(self.files, outputs, strict=True)
        ]
        self._cancel.clear()
        self._set_busy(_("Checking your certificate…"))
        services = self._services

        def work() -> None:
            try:
                with services.open_token() as token:
                    items = sign_pdf_batch(
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
        """RF-082: one history row per document the batch tried to sign."""
        check, history = self._check, self._services.history()
        if check is None or history is None:
            return
        for item in items:
            if item.outcome is Outcome.SKIPPED:
                continue
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
        dialog = Gtk.FileDialog(title=_("Export Report"), initial_name=_("batch-report.csv"))

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
        self.files = [(path, sha) for path, sha in self.files if path not in signed]
        self.items = None
        self._show_files()
        self._back_to_form()


def _local_paths(files: Iterable[Gio.File]) -> list[Path]:
    return [Path(path) for file in files if (path := file.get_path()) is not None]


def _group_with(widget: Gtk.Widget) -> Adw.PreferencesGroup:
    group = Adw.PreferencesGroup()
    group.add(widget)
    return group
