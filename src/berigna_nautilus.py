# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 noggalito
"""Nautilus extension: sign and verify with berigna from the context menu (RF-070).

"Firmar con berigna" is offered for files and folders: several files, or a folder, open the
batch page (CU-04). "Verificar firma" is offered for a single file, which berigna verifies or
signs according to its content. Both actions hand the selection to berigna, which receives it
in the running instance through D-Bus (RF-073); this extension never reads the files.

The menu labels come from the berigna catalogue (ADR-0011, ADR-0015), which the package
``berigna`` installs; ``berigna-nautilus`` depends on it (BRG-DSP-001 §1).
"""

import gettext
import logging
from collections.abc import Callable, Sequence
from typing import Any

import gi

# Nautilus 49 and later (GNOME 49; Ubuntu 26.04 has Nautilus 50) publish the API as 4.1, with
# the same menu provider; Nautilus 48 (Debian 13) as 4.0. Asking only for 4.0 left the menu
# out of Ubuntu 26.04 (found on 2026-11-08 by the import check of the installed package).
try:
    gi.require_version("Nautilus", "4.1")
except ValueError:
    gi.require_version("Nautilus", "4.0")
from gi.repository import Gio, GObject, Nautilus  # noqa: E402

APP_INFO_ID = "com.noggalito.Berigna.desktop"
ICON = "com.noggalito.Berigna-symbolic"
MENU_PREFIX = "BerignaMenuProvider::"

log = logging.getLogger(__name__)
_ = gettext.translation("berigna", fallback=True).gettext


def _is_local(file: Any) -> bool:
    """Only files of this computer: berigna cannot open remote locations."""
    return file.get_uri_scheme() == "file"


def _launch(_menu: Any, files: Sequence[Any]) -> bool:
    """Open berigna with ``files``; False when its desktop entry is missing.

    Connected to the "activate" signal, so GObject passes the menu item first.
    """
    app_info = Gio.DesktopAppInfo.new(APP_INFO_ID)
    if app_info is None:  # berigna is not installed: the package depends on it
        log.error("the berigna desktop entry was not found: %s", APP_INFO_ID)
        return False
    app_info.launch_uris([file.get_uri() for file in files], None)
    return True


def _menu_item(action: str, label: str, callback: Callable[..., bool], files: Sequence[Any]) -> Any:
    """A Nautilus.MenuItem for ``action`` that calls ``callback`` with the selection."""
    item = Nautilus.MenuItem(name=f"{MENU_PREFIX}{action}", label=label, tip=label, icon=ICON)
    item.connect("activate", callback, files)
    return item


class BerignaMenuProvider(GObject.GObject, Nautilus.MenuProvider):
    """The "Firmar con berigna" and "Verificar firma" items of files (RF-070)."""

    def get_file_items(self, files: Sequence[Any]) -> list[Any]:
        if not any(_is_local(file) for file in files):
            return []
        items = [_menu_item("firmar", _("Firmar con berigna"), _launch, files)]
        if len(files) == 1 and not files[0].is_directory():
            items.append(_menu_item("verificar", _("Verificar firma"), _launch, files))
        return items
