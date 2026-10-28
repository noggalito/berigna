# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Calú
"""Language of the interface (ADR-0015) and translation of the compiled views.

GTK translates ``translatable="yes"`` strings with the C library's gettext, which ignores
``LANGUAGE`` under the C locale and would then show the English source (seen with ``LANG=C``
and ``C.UTF-8``). berigna translates the views itself instead, with the catalogues and the
fallbacks of :mod:`berigna.core.i18n`, so the interface never depends on which locales are
generated and Quechua strings still pending fall back to es_PE, never to English.

The language can change while the program runs: the window is rebuilt from the views.
"""

import gettext
import os
from collections.abc import Mapping

from lxml import etree

from berigna.core.i18n import Language, resolve_language, system_preferences, translations

# Values of the GSettings key "ui-language".
SYSTEM = "system"

_language = Language.ES_PE
_catalogue: gettext.NullTranslations = translations(Language.ES_PE)


def N_(message: str) -> str:
    return message


def choose_language(setting: str, environ: Mapping[str, str] | None = None) -> Language:
    """The language for the ``ui-language`` setting (``system``, ``es_PE`` or ``quz_PE``)."""
    if setting == SYSTEM:
        return resolve_language(system_preferences(environ))
    return Language(setting)


def set_language(language: Language) -> None:
    """Use ``language`` from now on, for berigna's strings and, as far as possible, GTK's."""
    global _language, _catalogue
    _language = language
    _catalogue = translations(language)
    # GTK's own strings (file chooser, standard buttons) come from its own catalogue.
    os.environ["LANGUAGE"] = "quz:es_PE" if language is Language.QUZ_PE else "es_PE"


def current_language() -> Language:
    return _language


def catalogue() -> gettext.NullTranslations:
    return _catalogue


def _(message: str) -> str:
    return _catalogue.gettext(message)


def ngettext(singular: str, plural: str, n: int) -> str:
    return _catalogue.ngettext(singular, plural, n)


def translate_view(xml: bytes) -> str:
    """Translate the ``translatable`` strings of a GtkBuilder view into the current language."""
    root = etree.fromstring(xml, parser=etree.XMLParser(resolve_entities=False, no_network=True))
    for element in root.iter():
        if element.get("translatable") not in ("yes", "true", "1"):
            continue
        context = element.get("context")
        text = element.text or ""
        element.text = _catalogue.pgettext(context, text) if context else _catalogue.gettext(text)
        for attribute in ("translatable", "context", "comments"):
            element.attrib.pop(attribute, None)
    return etree.tostring(root, encoding="unicode")
