# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""History page (RF-082): the documents signed and verified, for the user's own control.

Newest first, with a search over file names, signer and SHA-256; it can be exported to CSV
and cleared. It is switched off, and the full paths kept, in Preferences → General.
"""

from pathlib import Path
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from berigna.core.files import dated_name, write_atomically  # noqa: E402
from berigna.core.history import Entry, History, Kind, history_csv  # noqa: E402
from berigna.core.report.explanations import explain_error, format_time  # noqa: E402
from berigna.ui.i18n import _, catalogue, current_language  # noqa: E402
from berigna.ui.signing import SigningServices  # noqa: E402
from berigna.ui.widgets import brand_markup  # noqa: E402

if TYPE_CHECKING:
    from berigna.ui.window import MainWindow

SHOWN = 500  # rows shown; the export has them all


def entry_subtitle(entry: Entry) -> str:
    """When, what and how it went, in one line."""
    when = format_time(entry.moment, _)
    if entry.kind is Kind.VERIFY:
        what = _("Verified: {passed} of {total} signatures valid").format(
            passed=(entry.detail or "0/0").split("/")[0],
            total=(entry.detail or "0/0").split("/")[-1],
        )
    elif entry.result == "ok":
        what = _("Signed ({level}) as {name}").format(
            level=entry.level or "", name=entry.signed_name or ""
        )
    else:
        reason = explain_error(entry.detail or "ERR-000", catalogue()) or ""
        what = _("Not signed: {reason}").format(reason=reason)
    return f"{when} · {what}"


class HistoryPage:
    def __init__(self, window: "MainWindow", services: SigningServices) -> None:
        self._window = window
        self._services = services
        self.entries: list[Entry] = []

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.search = Gtk.SearchEntry(
            placeholder_text=_("Search by name, signer or SHA-256"),
            margin_top=12,
            margin_start=12,
            margin_end=12,
        )
        self.search.connect("search-changed", lambda _e: self.refresh())
        content.append(Adw.Clamp(maximum_size=720, child=self.search))
        self._stack = Gtk.Stack(vexpand=True)
        self._list = Adw.PreferencesPage()
        self.group = Adw.PreferencesGroup()
        self._list.add(self.group)
        self._rows: list[Gtk.Widget] = []
        self._stack.add_named(self._list, "list")
        self.empty = Adw.StatusPage(icon_name="document-open-recent-symbolic")
        self._stack.add_named(self.empty, "empty")
        content.append(self._stack)

        self._export = Gtk.Button(
            icon_name="document-save-symbolic", tooltip_text=_("Export to CSV")
        )
        self._export.connect("clicked", lambda _b: self._choose_export())
        self._clear = Gtk.Button(icon_name="user-trash-symbolic", tooltip_text=_("Clear History"))
        self._clear.connect("clicked", lambda _b: self._confirm_clear())
        self.page = window.page(_("History"), "history", content, [self._clear, self._export])
        self.refresh()

    def _history(self) -> History | None:
        return self._services.history()

    def refresh(self) -> None:
        history = self._history()
        self.entries = history.entries(self.search.get_text()) if history else []
        for row in self._rows:
            self.group.remove(row)
        self._rows = []
        for entry in self.entries[:SHOWN]:
            row = Adw.ActionRow(
                title=entry.file_name,
                subtitle=brand_markup(entry_subtitle(entry)),
                subtitle_lines=0,
                use_markup=False,
            )
            ok = entry.result in ("ok", "TOTAL-PASSED")
            icon = Gtk.Image(
                icon_name="object-select-symbolic" if ok else "dialog-warning-symbolic"
            )
            icon.add_css_class("success" if ok else "warning")
            row.add_prefix(icon)
            self.group.add(row)
            self._rows.append(row)
        self.group.set_description(
            _(
                "Kept only on this computer. It is a record for your own control; the signed "
                "documents are the evidence."
            )
        )
        if history is None:
            self.empty.set_title(_("The history is switched off"))
            self.empty.set_description(_("Switch it on in Preferences → General."))
        elif self.search.get_text().strip():
            self.empty.set_title(_("Nothing found"))
            self.empty.set_description("")
        else:
            self.empty.set_title(_("Nothing signed or verified yet"))
            self.empty.set_description("")
        self._stack.set_visible_child_name("list" if self.entries else "empty")
        self._export.set_sensitive(bool(self.entries))
        self._clear.set_sensitive(history is not None and bool(self.entries))

    def report(self) -> str:
        history = self._history()
        return history_csv(history.entries() if history else [], current_language())

    def _choose_export(self) -> None:
        dialog = Gtk.FileDialog(
            title=_("Export to CSV"), initial_name=dated_name(_("berigna-history.csv"))
        )

        def chosen(dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
            try:
                file = dialog.save_finish(result)
            except GLib.Error:
                return
            path = file.get_path()
            if path is not None:
                self.export(Path(path))

        dialog.save(self._window.window, None, chosen)

    def export(self, path: Path) -> None:
        try:
            write_atomically(path, self.report().encode("utf-8"), replace=True)
        except OSError:
            self._window.toast(_("The history could not be saved."))
        else:
            self._window.toast(_("History exported."))

    def _confirm_clear(self) -> None:
        dialog = Adw.AlertDialog(
            heading=_("Clear the History?"),
            body=_(
                "Every row is deleted from this computer. The signed documents are not touched."
            ),
        )
        dialog.add_response("cancel", _("_Cancel"))
        dialog.add_response("clear", _("C_lear"))
        dialog.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.connect("response", self._on_clear_response)
        dialog.present(self._window.window)

    def _on_clear_response(self, _dialog: Adw.AlertDialog, response: str) -> None:
        if response == "clear":
            self.clear()

    def clear(self) -> None:
        history = self._history()
        if history is not None:
            history.clear()
        self.refresh()
        self._window.toast(_("History cleared."))
