# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Contextual help: a "More information" button that opens the online help (ADR-0017).

The pages live at ``https://berigna.noggalito.com/ayuda/<version>/<language>/<topic>``: the
version is that of the running program (major.minor), so that the help always describes
what the user sees. Only the version, the language and the topic go in the address.
"""

import enum

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from berigna import __version__  # noqa: E402
from berigna.core.i18n import Language  # noqa: E402
from berigna.ui.i18n import _, current_language  # noqa: E402

HELP_SITE = "https://berigna.noggalito.com/ayuda"


class HelpTopic(enum.Enum):
    SIGNATURE_LEVELS = "niveles-de-firma"
    HASH_ALGORITHM = "algoritmo-de-hash"
    TIMESTAMPING_AUTHORITY = "autoridad-de-sellado-de-tiempo"
    NETWORK_TIMEOUT = "tiempo-de-espera"
    PROXY = "proxy"
    TRUSTED_LIST = "lista-de-confianza"


def help_url(topic: HelpTopic) -> str:
    version = ".".join(__version__.split(".")[:2])
    language = "quz" if current_language() is Language.QUZ_PE else "es"
    return f"{HELP_SITE}/{version}/{language}/{topic.value}"


def help_button(topic: HelpTopic) -> Gtk.Button:
    button = Gtk.Button(
        icon_name="help-about-symbolic",
        tooltip_text=_("More Information"),
        valign=Gtk.Align.CENTER,
    )
    button.add_css_class("flat")
    button.update_property([Gtk.AccessibleProperty.LABEL], [_("More Information")])
    button.connect("clicked", lambda b: open_help(b, topic))
    return button


def open_help(widget: Gtk.Widget, topic: HelpTopic) -> None:
    launcher = Gtk.UriLauncher(uri=help_url(topic))
    launcher.launch(widget.get_root(), None, None)
